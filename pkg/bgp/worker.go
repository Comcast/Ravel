package bgp

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/comcast/ravel/pkg/stats"
	"github.com/comcast/ravel/pkg/system"
	"github.com/comcast/ravel/pkg/types"
)

const (
	addrKindIPV4 = "ipv4"
	addrKindIPV6 = "ipv6"
)

type BGPWorker interface {
	Start() error
	Stop() error
}

type bgpserver struct {
	sync.Mutex

	services map[string]string

	watcher    system.Watcher
	ipLoopback system.IP
	ipPrimary  system.IP
	ipvs       system.IPVS
	bgp        Controller

	doneChan chan struct{}

	lastInboundUpdate time.Time
	lastReconfigure   time.Time

	nodes             types.NodesList
	config            *types.ClusterConfig
	lastAppliedConfig *types.ClusterConfig
	newConfig         bool
	nodeChan          chan types.NodesList
	configChan        chan *types.ClusterConfig
	ctxWatch          context.Context
	cxlWatch          context.CancelFunc

	ctx     context.Context
	logger  logrus.FieldLogger
	metrics *stats.WorkerStateMetrics
}

func NewBGPWorker(
	ctx context.Context,
	configKey string,
	watcher system.Watcher,
	ipLoopback system.IP,
	ipPrimary system.IP,
	ipvs system.IPVS,
	bgpController Controller,
	logger logrus.FieldLogger) (BGPWorker, error) {

	logger.Debugf("Enter NewBGPWorker()")
	defer logger.Debugf("Exit NewBGPWorker()")

	r := &bgpserver{
		watcher:    watcher,
		ipLoopback: ipLoopback,
		ipPrimary:  ipPrimary,
		ipvs:       ipvs,
		bgp:        bgpController,

		services: map[string]string{},

		doneChan:   make(chan struct{}),
		configChan: make(chan *types.ClusterConfig, 1),
		nodeChan:   make(chan types.NodesList, 1),

		ctx:     ctx,
		logger:  logger,
		metrics: stats.NewWorkerStateMetrics(stats.KindBGP, configKey),
	}

	logger.Debugf("Exit NewBGPWorker(), return %+v", r)
	return r, nil
}

func (b *bgpserver) Stop() error {
	b.cxlWatch()

	b.logger.Info("blocking until periodic tasks complete")
	select {
	case <-b.doneChan:
	case <-time.After(5000 * time.Millisecond):
	}

	ctxDestroy, cxl := context.WithTimeout(context.Background(), 5000*time.Millisecond)
	defer cxl()

	b.logger.Info("starting cleanup")
	err := b.cleanup(ctxDestroy)
	b.logger.Infof("cleanup complete. error=%v", err)
	return err
}

func (b *bgpserver) cleanup(ctx context.Context) error {
	errs := []string{}

	// delete all k2i addresses from loopback
	if err := b.ipLoopback.Teardown(ctx); err != nil {
		errs = append(errs, fmt.Sprintf("cleanup - failed to remove ip addresses - %v", err))
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%v", errs)
}

func (b *bgpserver) setup() error {
	b.logger.Debugf("Enter func (b *bgpserver) setup()\n")
	defer b.logger.Debugf("Exit func (b *bgpserver) setup()\n")

	ctxWatch, cxlWatch := context.WithCancel(b.ctx)
	b.cxlWatch = cxlWatch
	b.ctxWatch = ctxWatch

	// register the watcher for both nodes and the configmap
	b.watcher.Nodes(ctxWatch, "bpg-nodes", b.nodeChan)
	b.watcher.ConfigMap(ctxWatch, "bgp-configmap", b.configChan)
	return nil
}

func (b *bgpserver) Start() error {

	b.logger.Debugf("Enter func (b *bgpserver) Start()\n")
	defer b.logger.Debugf("Exit func (b *bgpserver) Start()\n")

	err := b.setup()
	if err != nil {
		return err
	}

	go b.watches()
	go b.periodic()
	return nil
}

// watchServiceUpdates calls the watcher every 100ms to retrieve an updated
// list of service definitions. It then iterates over the map of services and
// builds a new map of namespace/service:port identity to clusterIP:port
func (b *bgpserver) watchServiceUpdates() {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-t.C:
			services := map[string]string{}
			for svcName, svc := range b.watcher.Services() {
				if svc.Spec.ClusterIP == "" {
					continue
				} else if svc.Spec.Ports == nil {
					continue
				}
				for _, port := range svc.Spec.Ports {
					identifier := svcName + ":" + port.Name
					addr := svc.Spec.ClusterIP + ":" + strconv.Itoa(int(port.Port))
					services[identifier] = addr
				}
			}
			b.Lock()
			b.services = services
			b.Unlock()
		}
	}
}

func (b *bgpserver) getClusterAddr(identity string) (string, error) {
	b.Lock()
	defer b.Unlock()
	ip, ok := b.services[identity]
	if !ok {
		return "", fmt.Errorf("not found")
	}
	return ip, nil
}

func (b *bgpserver) configure() error {
	logger := b.logger.WithFields(logrus.Fields{"protocol": "ipv4"})
	logger.Debug("Enter func (b *bgpserver) configure()")
	defer logger.Debug("Exit func (b *bgpserver) configure()")

	// add/remove vip addresses on loopback
	err := b.setAddresses()
	if err != nil {
		return err
	}

	configuredAddrs, err := b.bgp.Get(b.ctx)
	if err != nil {
		return err
	}

	// Do something BGP-ish with VIPs from configmap
	// This only adds, and never removes, VIPs
	logger.Debug("applying bgp settings")
	addrs := []string{}
	for ip, _ := range b.config.Config {
		addrs = append(addrs, string(ip))
	}
	err = b.bgp.Set(b.ctx, addrs, configuredAddrs)
	if err != nil {
		return err
	}

	// Set IPVS rules based on VIPs, pods associated with each VIP
	// and some other settings bgpserver receives from RDEI.
	err = b.ipvs.SetIPVS(b.nodes, b.config, b.logger)
	if err != nil {
		return fmt.Errorf("unable to configure ipvs with error %v", err)
	}
	b.logger.Debug("IPVS configured")
	b.lastReconfigure = time.Now()

	return nil
}

func (b *bgpserver) configure6() error {
	logger := b.logger.WithFields(logrus.Fields{"protocol": "ipv6"})

	logger.Debug("starting configuration")
	// add vip addresses to loopback
	err := b.setAddresses6()
	if err != nil {
		return err
	}

	addrs := []string{}
	for ip := range b.config.Config6 {
		addrs = append(addrs, string(ip))
	}

	err = b.bgp.SetV6(b.ctx, addrs)
	if err != nil {
		return err
	}

	// Set IPVS rules based on VIPs, pods associated with each VIP
	// and some other settings bgpserver receives from RDEI.
	err = b.ipvs.SetIPVS6(b.nodes, b.config, b.logger)
	if err != nil {
		return fmt.Errorf("unable to configure ipvs with error %v", err)
	}
	b.logger.Debug("IPVS6 configured successfully")

	return nil
}

func (b *bgpserver) periodic() {
	b.logger.Debug("Enter func (b *bgpserver) periodic()\n")
	defer b.logger.Debug("Exit func (b *bgpserver) periodic()\n")

	// Queue Depth metric ticker
	queueDepthTicker := time.NewTicker(60 * time.Second)
	defer queueDepthTicker.Stop()

	bgpInterval := 2000 * time.Millisecond
	bgpTicker := time.NewTicker(bgpInterval)
	defer bgpTicker.Stop()

	b.logger.Infof("starting BGP periodic ticker, interval %v", bgpInterval)

	// every so many seconds, reapply configuration without checking parity
	reconfigureDuration := 30 * time.Second
	reconfigureTicker := time.NewTicker(reconfigureDuration)
	defer reconfigureTicker.Stop()

	for {
		select {
		case <-queueDepthTicker.C:
			b.metrics.QueueDepth(len(b.configChan))
			b.logger.Debugf("periodic - config=%+v", b.config)

		case <-reconfigureTicker.C:
			b.logger.Debugf("mandatory periodic reconfigure executing after %v", reconfigureDuration)
			start := time.Now()
			if err := b.configure(); err != nil {
				b.metrics.Reconfigure("critical", time.Now().Sub(start))
				b.logger.Errorf("unable to apply mandatory ipv4 reconfiguration. %v", err)
			}

			if err := b.configure6(); err != nil {
				b.metrics.Reconfigure("critical", time.Now().Sub(start))
				b.logger.Errorf("unable to apply mandatory ipv6 reconfiguration. %v", err)
			}

			b.metrics.Reconfigure("complete", time.Now().Sub(start))
		case <-bgpTicker.C:
			b.logger.Debug("BGP ticker expired, checking parity & etc")
			b.performReconfigure()

		case <-b.ctx.Done():
			b.logger.Info("periodic(): parent context closed. exiting run loop")
			b.doneChan <- struct{}{}
			return
		case <-b.ctxWatch.Done():
			b.logger.Info("periodic(): watch context closed. exiting run loop")
			return
		}
	}
}

func (b *bgpserver) noUpdatesReady() bool {
	return b.lastReconfigure.Sub(b.lastInboundUpdate) > 0
}

func (b *bgpserver) setAddresses6() error {
	// pull existing
	_, configuredV6, err := b.ipLoopback.Get()
	if err != nil {
		return err
	}

	// get desired set VIP addresses
	desired := []string{}
	for v6 := range b.config.Config6 {
		desired = append(desired, string(v6))
	}

	removals, additions := b.ipLoopback.Compare6(configuredV6, desired)
	b.logger.Debugf("additions=%v removals=%v", additions, removals)
	b.metrics.LoopbackAdditions(len(additions), addrKindIPV6)
	b.metrics.LoopbackRemovals(len(removals), addrKindIPV6)
	b.metrics.LoopbackTotalDesired(len(desired), addrKindIPV6)
	b.metrics.LoopbackConfigHealthy(1, addrKindIPV6)

	for _, addr := range removals {
		b.logger.WithFields(logrus.Fields{"device": b.ipLoopback.Device(), "addr": addr, "action": "deleting"}).Info()
		if err := b.ipLoopback.Del(addr); err != nil {
			b.metrics.LoopbackRemovalErr(1, addrKindIPV6)
			b.metrics.LoopbackConfigHealthy(0, addrKindIPV6)
			return err
		}
	}
	for _, addr := range additions {
		b.logger.WithFields(logrus.Fields{"device": b.ipLoopback.Device(), "addr": addr, "action": "adding"}).Info()
		if err := b.ipLoopback.Add(addr); err != nil {
			b.metrics.LoopbackAdditionErr(1, addrKindIPV6)
			b.metrics.LoopbackConfigHealthy(0, addrKindIPV6)
			return err
		}
	}

	return nil
}

// setAddresses adds or removes IP address from the loopback device (lo).
// The IP addresses should be VIPs, from the configmap that a kubernetes
// watcher gives to a bgpserver in func (b *bgpserver) watches()
func (b *bgpserver) setAddresses() error {
	// pull existing
	configuredV4, _, err := b.ipLoopback.Get()
	if err != nil {
		return err
	}

	// get desired set VIP addresses
	desired := []string{}
	for ip, _ := range b.config.Config {
		desired = append(desired, string(ip))
	}

	removals, additions := b.ipLoopback.Compare4(configuredV4, desired)
	b.logger.Debugf("additions_v4=%v removals_v4=%v", additions, removals)
	b.metrics.LoopbackAdditions(len(additions), addrKindIPV4)
	b.metrics.LoopbackRemovals(len(removals), addrKindIPV4)
	b.metrics.LoopbackTotalDesired(len(desired), addrKindIPV4)
	b.metrics.LoopbackConfigHealthy(1, addrKindIPV4)

	for _, addr := range removals {
		b.logger.WithFields(logrus.Fields{"device": b.ipLoopback.Device(), "addr": addr, "action": "deleting"}).Info()
		if err := b.ipLoopback.Del(addr); err != nil {
			b.metrics.LoopbackRemovalErr(1, addrKindIPV4)
			b.metrics.LoopbackConfigHealthy(0, addrKindIPV4)
			return err
		}
	}
	for _, addr := range additions {
		b.logger.WithFields(logrus.Fields{"device": b.ipLoopback.Device(), "addr": addr, "action": "adding"}).Info()
		if err := b.ipLoopback.Add(addr); err != nil {
			b.metrics.LoopbackAdditionErr(1, addrKindIPV4)
			b.metrics.LoopbackConfigHealthy(0, addrKindIPV4)
			return err
		}
	}

	return nil
}

// watches just selects from node updates and config updates channels,
// setting appropriate instance variable in the receiver b.
// func periodic() will act on any changes in nodes list or config
// when one or more of its timers expire.
func (b *bgpserver) watches() {
	b.logger.Debugf("Enter func (b *bgpserver) watches()\n")
	defer b.logger.Debugf("Exit func (b *bgpserver) watches()\n")

	for {
		select {

		case nodes := <-b.nodeChan:
			b.logger.Debug("recv nodeChan")
			if types.NodesEqual(b.nodes, nodes, b.logger) {
				b.logger.Debug("NODES ARE EQUAL")
				b.metrics.NodeUpdate("noop")
				continue
			}
			b.metrics.NodeUpdate("updated")
			b.logger.Debug("NODES ARE NOT EQUAL")
			b.Lock()
			b.nodes = nodes

			b.lastInboundUpdate = time.Now()
			b.Unlock()

		case configs := <-b.configChan:
			b.logger.Debug("recv configChan")
			b.Lock()
			b.config = configs
			b.newConfig = true
			b.lastInboundUpdate = time.Now()
			b.Unlock()
			b.metrics.ConfigUpdate()

		// Administrative
		case <-b.ctx.Done():
			b.logger.Debugf("parent context closed. exiting run loop")
			return
		case <-b.ctxWatch.Done():
			b.logger.Debugf("watch context closed. exiting run loop")
			return
		}

	}
}

func (b *bgpserver) configReady() bool {
	newConfig := false
	b.Lock()
	if b.newConfig {
		newConfig = true
		b.newConfig = false
	}
	b.Unlock()
	return newConfig
}

// performReconfigure decides whether bgpserver has new
// info that possibly results in an IPVS reconfigure,
// checks to see if that new info would result in an IPVS
// reconfigure, then does it if so.
func (b *bgpserver) performReconfigure() {

	if b.noUpdatesReady() {
		// last update happened before the last reconfigure
		return
	}

	start := time.Now()

	// these are the VIP addresses
	// get both the v4 and v6 to use in CheckConfigParity below
	addressesV4, addressesV6, err := b.ipLoopback.Get()
	if err != nil {
		b.metrics.Reconfigure("error", time.Now().Sub(start))
		b.logger.Infof("unable to compare configurations with error %v", err)
		return
	}

	// splice together to compare against the internal state of configs
	// addresses is sorted within the CheckConfigParity function
	addresses := append(addressesV4, addressesV6...)

	// compare configurations and apply new IPVS rules if they're different
	same, err := b.ipvs.CheckConfigParity(b.nodes, b.config, addresses, b.configReady())
	if err != nil {
		b.metrics.Reconfigure("error", time.Now().Sub(start))
		b.logger.Infof("unable to compare configurations with error %v", err)
		return
	}

	if same {
		b.logger.Debug("parity same")
		b.metrics.Reconfigure("noop", time.Now().Sub(start))
		return
	}

	b.logger.Debug("parity different, reconfiguring")
	if err := b.configure(); err != nil {
		b.metrics.Reconfigure("critical", time.Now().Sub(start))
		b.logger.Infof("unable to apply ipv4 configuration. %v", err)
		return
	}

	if err := b.configure6(); err != nil {
		b.metrics.Reconfigure("critical", time.Now().Sub(start))
		b.logger.Infof("unable to apply ipv6 configuration. %v", err)
		return
	}
	b.metrics.Reconfigure("complete", time.Now().Sub(start))
}
