package bgp

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Comcast/Ravel/pkg/stats"
	"github.com/Comcast/Ravel/pkg/system"
	"github.com/Comcast/Ravel/pkg/types"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

const (
	addrKindIPV4 = "ipv4"
	addrKindIPV6 = "ipv6"
)

// TODO - remove when not pinning to debug
func init() {
	log.SetLevel(log.DebugLevel)
}

// BGPWorker describes a BGP worker that can advertise BGP routes and communities
type BGPWorker interface {
	Start() error
	Stop() error
}

type bgpserver struct {
	sync.Mutex

	services map[string]string

	watcher   system.Watcher
	ipDevices system.IP
	ipPrimary system.IP
	ipvs      system.IPVS
	bgp       Controller
	devices   map[string]string

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

	communities []string
}

// NewBGPWorker creates a new BGPWorker, which configures BGP for all VIPs
func NewBGPWorker(ctx context.Context, configKey string, watcher system.Watcher, ipDevices system.IP, ipPrimary system.IP, ipvs system.IPVS, bgpController Controller, communities []string, logger logrus.FieldLogger) (BGPWorker, error) {

	log.Debugln("bgp: Creating new BGP worker")

	r := &bgpserver{
		watcher:   watcher,
		ipDevices: ipDevices,
		ipPrimary: ipPrimary,
		ipvs:      ipvs,
		bgp:       bgpController,
		devices:   map[string]string{},

		services: map[string]string{},

		doneChan:   make(chan struct{}),
		configChan: make(chan *types.ClusterConfig, 1),
		nodeChan:   make(chan types.NodesList, 1),

		ctx:     ctx,
		logger:  logger,
		metrics: stats.NewWorkerStateMetrics(stats.KindBGP, configKey),

		communities: communities,
	}

	return r, nil
}

func (b *bgpserver) Stop() error {
	log.Debugln("bgp: Stopping BGPServer")
	b.cxlWatch()

	log.Infoln("bgp: blocking until periodic tasks complete")
	select {
	case <-b.doneChan:
	case <-time.After(5000 * time.Millisecond):
	}

	ctxDestroy, cxl := context.WithTimeout(context.Background(), 5000*time.Millisecond)
	defer cxl()

	log.Infoln("bgp: starting cleanup")
	err := b.cleanup(ctxDestroy)
	log.Infoln("bgp: cleanup completed")
	b.logger.Infof("cleanup complete. error=%v", err)
	return err
}

func (b *bgpserver) cleanup(ctx context.Context) error {
	errs := []string{}

	// delete all k2i addresses from loopback
	if err := b.ipDevices.Teardown(ctx, b.config.Config, b.config.Config6); err != nil {
		errs = append(errs, fmt.Sprintf("cleanup - failed to remove ip addresses - %v", err))
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%v", errs)
}

func (b *bgpserver) setup() error {
	log.Debugln("Enter func (b *bgpserver) setup()")
	defer log.Debugln("Exit func (b *bgpserver) setup()")

	ctxWatch, cxlWatch := context.WithCancel(b.ctx)
	b.cxlWatch = cxlWatch
	b.ctxWatch = ctxWatch

	// register the watcher for both nodes and the configmap
	b.watcher.Nodes(ctxWatch, "bpg-nodes", b.nodeChan)
	b.watcher.ConfigMap(ctxWatch, "bgp-configmap", b.configChan)
	return nil
}

func (b *bgpserver) Start() error {
	log.Debugln("bgp: Starting BGPServer")

	log.Debugln("bgp: Enter func (b *bgpserver) Start()")
	defer log.Debugln("Exit func (b *bgpserver) Start()")

	err := b.setup()
	if err != nil {
		return err
	}

	log.Debugln("bgp: starting watches and periodic checks")
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
		log.Debugln("bgp: starting polling for service updates...")
		select {
		case <-b.ctx.Done():
			return
		case <-t.C:
			log.Debugln("bgp: polling for service...")
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
		return "", fmt.Errorf("bgp: cluster address not found for identity: %s", identity)
	}
	return ip, nil
}

func (b *bgpserver) configure() error {
	log.Debugln("bgp: configuring BGPServer")
	// logger := b.logger.WithFields(logrus.Fields{"protocol": "ipv4"})
	log.Debugln("bgp: Enter func (b *bgpserver) configure()")
	defer log.Debugln("bgp: Exit func (b *bgpserver) configure()")

	// add/remove vip addresses on the interface specified for this vip
	log.Debugln("bgp: Setting addresses")
	err := b.setAddresses()
	if err != nil {
		return err
	}
	log.Debugln("bgp: Setting addresses complete")

	configuredAddrs, err := b.bgp.Get(b.ctx)
	if err != nil {
		return err
	}

	// Do something BGP-ish with VIPs from configmap
	// This only adds, and never removes, VIPs
	log.Debug("bgp: applying bgp settings")
	addrs := []string{}
	for ip, _ := range b.config.Config {
		addrs = append(addrs, string(ip))
	}
	err = b.bgp.Set(b.ctx, addrs, configuredAddrs, b.communities)
	if err != nil {
		return err
	}
	log.Debugln("bgp: done applying bgp settings")

	// Set IPVS rules based on VIPs, pods associated with each VIP
	// and some other settings bgpserver receives from RDEI.
	log.Debugln("bgp: Setting IPVS settings")
	err = b.ipvs.SetIPVS(b.nodes, b.config, b.logger)
	if err != nil {
		return fmt.Errorf("bgp: unable to configure ipvs with error %v", err)
	}
	log.Debugln("bgp: IPVS configured")
	b.lastReconfigure = time.Now()

	return nil
}

func (b *bgpserver) configure6() error {
	// logger := b.logger.WithFields(logrus.Fields{"protocol": "ipv6"})

	log.Debugln("bgp: starting ipv6 configuration")
	// add vip addresses to loopback
	err := b.setAddresses6()
	if err != nil {
		return err
	}

	addrs := []string{}
	for ip := range b.config.Config6 {
		addrs = append(addrs, string(ip))
	}

	// set BGP announcements
	err = b.bgp.SetV6(b.ctx, addrs, b.communities)
	if err != nil {
		return err
	}

	// Set IPVS rules based on VIPs, pods associated with each VIP
	// and some other settings bgpserver receives from RDEI.
	err = b.ipvs.SetIPVS6(b.nodes, b.config, b.logger)
	if err != nil {
		return fmt.Errorf("bgp: unable to configure ipvs with error %v", err)
	}
	log.Debugln("bgp: IPVS6 configured successfully")

	return nil
}

func (b *bgpserver) periodic() {
	log.Debugln("bgp: Enter func (b *bgpserver) periodic()\n")
	defer log.Debugln("bgp: Exit func (b *bgpserver) periodic()\n")

	// Queue Depth metric ticker
	queueDepthTicker := time.NewTicker(60 * time.Second)
	defer queueDepthTicker.Stop()

	bgpInterval := time.Second * 2
	bgpTicker := time.NewTicker(bgpInterval)
	defer bgpTicker.Stop()

	log.Infof("bgp: starting BGP periodic ticker, interval %v\n", bgpInterval)

	// every so many seconds, reapply configuration without checking parity
	reconfigureDuration := 30 * time.Second
	reconfigureTicker := time.NewTicker(reconfigureDuration)
	defer reconfigureTicker.Stop()

	for {
		select {
		case <-queueDepthTicker.C:
			b.metrics.QueueDepth(len(b.configChan))
			log.Debugf("bgp: periodic - config=%+v\n", b.config)

		case <-reconfigureTicker.C:
			log.Debugf("bgp: mandatory periodic reconfigure executing after %v", reconfigureDuration)
			start := time.Now()
			if err := b.configure(); err != nil {
				b.metrics.Reconfigure("critical", time.Now().Sub(start))
				log.Errorf("bgp: unable to apply mandatory ipv4 reconfiguration. %v", err)
			}

			if err := b.configure6(); err != nil {
				b.metrics.Reconfigure("critical", time.Now().Sub(start))
				log.Errorf("bgp: unable to apply mandatory ipv6 reconfiguration. %v", err)
			}

			b.metrics.Reconfigure("complete", time.Now().Sub(start))
		case <-bgpTicker.C:
			log.Debugln("bgp: BGP ticker expired, checking parity & etc")
			b.performReconfigure()

		case <-b.ctx.Done():
			log.Infoln("bgp: periodic(): parent context closed. exiting run loop")
			b.doneChan <- struct{}{}
			return
		case <-b.ctxWatch.Done():
			log.Infoln("bgp: periodic(): watch context closed. exiting run loop")
			return
		}
	}
}

func (b *bgpserver) noUpdatesReady() bool {
	return b.lastReconfigure.Sub(b.lastInboundUpdate) > 0
}

func (b *bgpserver) setAddresses6() error {

	log.Infoln("bgp: fetching dummy interfaces via bgpserver setAddresses6")

	// pull existing
	_, configuredV6, err := b.ipDevices.Get()
	if err != nil {
		return err
	}

	// get desired set VIP addresses
	desired := []string{}
	devToAddr := map[string]string{}
	for ip := range b.config.Config6 {
		devName := b.ipDevices.Device(string(ip), true)
		desired = append(desired, devName)
		devToAddr[devName] = string(ip)
	}

	removals, additions := b.ipDevices.Compare6(configuredV6, desired)

	b.logger.Debugf("additions=%v removals=%v", additions, removals)
	b.metrics.LoopbackAdditions(len(additions), addrKindIPV6)
	b.metrics.LoopbackRemovals(len(removals), addrKindIPV6)
	b.metrics.LoopbackTotalDesired(len(desired), addrKindIPV6)
	b.metrics.LoopbackConfigHealthy(1, addrKindIPV6)

	for _, device := range removals {
		b.logger.WithFields(logrus.Fields{"device": device, "action": "deleting"}).Info()
		if err := b.ipDevices.Del(device); err != nil {
			b.metrics.LoopbackRemovalErr(1, addrKindIPV6)
			b.metrics.LoopbackConfigHealthy(0, addrKindIPV6)
			return err
		}
	}
	for _, device := range additions {
		// add the device and configure
		addr := devToAddr[device]

		b.logger.WithFields(logrus.Fields{"device": device, "addr": addr, "action": "adding"}).Info()

		if err := b.ipDevices.Add6(addr); err != nil {
			b.metrics.LoopbackAdditionErr(1, addrKindIPV6)
			b.metrics.LoopbackConfigHealthy(0, addrKindIPV6)
			return err
		}
	}

	// now iterate across configured and see if we have a non-standard MTU
	// setting it where applicable
	err = b.ipDevices.SetMTU(b.config.MTUConfig6, true)
	if err != nil {
		return err
	}

	return nil
}

// setAddresses adds or removes IP address from the loopback device (lo).
// The IP addresses should be VIPs, from the configmap that a kubernetes
// watcher gives to a bgpserver in func (b *bgpserver) watches()
func (b *bgpserver) setAddresses() error {
	// pull existing
	log.Infoln("bgp: fetching dummy interfaces via bgpserver setAddresses")
	configuredV4, _, err := b.ipDevices.Get()
	if err != nil {
		return err
	}

	// get desired set VIP addresses
	desired := []string{}
	devToAddr := map[string]string{}
	for ip := range b.config.Config {
		devName := b.ipDevices.Device(string(ip), false)
		desired = append(desired, devName)
		devToAddr[devName] = string(ip)
	}

	removals, additions := b.ipDevices.Compare4(configuredV4, desired)
	b.logger.Debugf("additions_v4=%v removals_v4=%v", additions, removals)
	b.metrics.LoopbackAdditions(len(additions), addrKindIPV4)
	b.metrics.LoopbackRemovals(len(removals), addrKindIPV4)
	b.metrics.LoopbackTotalDesired(len(desired), addrKindIPV4)
	b.metrics.LoopbackConfigHealthy(1, addrKindIPV4)
	// "removals" is in the form of a fully qualified
	for _, device := range removals {
		b.logger.WithFields(logrus.Fields{"device": device, "action": "deleting"}).Info()
		// remove the device
		if err := b.ipDevices.Del(device); err != nil {
			b.metrics.LoopbackRemovalErr(1, addrKindIPV4)
			b.metrics.LoopbackConfigHealthy(0, addrKindIPV4)
			return err
		}
	}

	for _, device := range additions {
		// add the device and configure
		addr := devToAddr[device]
		b.logger.WithFields(logrus.Fields{"device": device, "addr": addr, "action": "adding"}).Info()
		if err := b.ipDevices.Add(addr); err != nil {
			b.metrics.LoopbackAdditionErr(1, addrKindIPV4)
			b.metrics.LoopbackConfigHealthy(0, addrKindIPV4)
			return err
		}
	}

	// now iterate across configured and see if we have a non-standard MTU
	// setting it where applicable
	// pull existing
	log.Debugln("bgp: setting BTP on devices")
	err = b.ipDevices.SetMTU(b.config.MTUConfig, false)
	if err != nil {
		return err
	}

	return nil
}

// watches just selects from node updates and config updates channels,
// setting appropriate instance variable in the receiver b.
// func periodic() will act on any changes in nodes list or config
// when one or more of its timers expire.
func (b *bgpserver) watches() {
	log.Debugf("bgp: Enter func (b *bgpserver) watches()\n")
	defer log.Debugf("bgp: Exit func (b *bgpserver) watches()\n")

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
			log.Debugln("bgp: parent context closed. exiting run loop")
			return
		case <-b.ctxWatch.Done():
			log.Debugf("bgp: watch context closed. exiting run loop\n")
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

	log.Debugln("bgp: running performReconfigure")

	if b.noUpdatesReady() {
		log.Debugln("bgp: no updates ready")
		// last update happened before the last reconfigure
		return
	}

	start := time.Now()

	// these are the VIP addresses
	// get both the v4 and v6 to use in CheckConfigParity below
	log.Infoln("bgp: fetching dummy interfaces via performReconfigure")
	addressesV4, addressesV6, err := b.ipDevices.Get()
	if err != nil {
		b.metrics.Reconfigure("error", time.Now().Sub(start))
		log.Errorf("bgp: unable to compare configurations with error %v\n", err)
		return
	}

	// splice together to compare against the internal state of configs
	// addresses is sorted within the CheckConfigParity function
	addresses := append(addressesV4, addressesV6...)

	log.Debugln("CheckConfigParity: bgpserver passing in these addresses:", addresses)
	// compare configurations and apply new IPVS rules if they're different
	same, err := b.ipvs.CheckConfigParity(b.nodes, b.config, addresses, b.configReady())
	if err != nil {
		b.metrics.Reconfigure("error", time.Now().Sub(start))
		log.Errorln("unable to compare configurations with error %v\n", err)
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
