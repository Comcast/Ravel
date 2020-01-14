package director

import (
	"context"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.comcast.com/viper-sde/kube2ipvs/pkg/iptables"
	"github.comcast.com/viper-sde/kube2ipvs/pkg/stats"
	"github.comcast.com/viper-sde/kube2ipvs/pkg/system"
	"github.comcast.com/viper-sde/kube2ipvs/pkg/types"
)

const (
	colocationModeDisabled = "disabled"
	colocationModeIPTables = "iptables"
	colocationModeIPVS     = "ipvs"
)

// TODO: instant startup

// A director is the control flow for kube2ipvs. It can only be started once, and it can only be stopped once.
type Director interface {
	Start() error
	Stop() error
}

type director struct {
	sync.Mutex

	// start/stop and backpropagation of internal errors
	isStarted bool
	doneChan  chan struct{}
	err       error

	// declarative state - this is what ought to be configured
	nodeName  string
	node      types.Node
	nodes     types.NodesList
	config    *types.ClusterConfig
	newConfig bool

	// inbound data sources
	nodeChan   chan types.NodesList
	configChan chan *types.ClusterConfig
	ctxWatch   context.Context
	cxlWatch   context.CancelFunc

	reconfiguring     bool
	lastInboundUpdate time.Time
	lastReconfigure   time.Time

	watcher  system.Watcher
	ipvs     system.IPVS
	ip       system.IP
	iptables iptables.IPTables

	// cli flag default false
	doCleanup          bool
	colocationMode     string
	forcedReconfigure  bool
	ipvsWeightOverride bool

	// boilerplate.  when this context is canceled, the director must cease all activties
	ctx     context.Context
	logger  logrus.FieldLogger
	metrics *stats.WorkerStateMetrics
}

func NewDirector(ctx context.Context, nodeName, configKey string, cleanup bool, watcher system.Watcher, ipvs system.IPVS, ip system.IP, ipt iptables.IPTables, colocationMode string, forcedReconfigure bool, logger logrus.FieldLogger) (Director, error) {
	d := &director{
		watcher:  watcher,
		ipvs:     ipvs,
		ip:       ip,
		nodeName: nodeName,

		iptables: ipt,

		doneChan:   make(chan struct{}),
		nodeChan:   make(chan types.NodesList, 1),
		configChan: make(chan *types.ClusterConfig, 1),

		doCleanup:         cleanup,
		ctx:               ctx,
		logger:            logger,
		metrics:           stats.NewWorkerStateMetrics(stats.KindDirector, configKey),
		colocationMode:    colocationMode,
		forcedReconfigure: forcedReconfigure,
	}

	return d, nil
}

func (d *director) Start() error {
	if d.isStarted {
		return fmt.Errorf("director has already been started. a director instance can only be started once!")
	}
	if d.reconfiguring {
		return fmt.Errorf("unable to Start. reconfiguration already in progress.")
	}
	d.setReconfiguring(true)
	defer func() { d.setReconfiguring(false) }()
	d.logger.Debugf("start called")

	// init
	d.isStarted = true
	d.doneChan = make(chan struct{})

	// set arp rules
	err := d.ip.SetARP()
	if err != nil {
		return fmt.Errorf("cleanup - failed to clear arp rules - %v", err)
	}

	if d.colocationMode != colocationModeIPTables {
		// cleanup any lingering iptables rules
		if err := d.iptables.Flush(); err != nil {
			return fmt.Errorf("cleanup - failed to flush iptables - %v", err)
		}
	}
	// If director is co-located with a realserver, the realserver
	// will deal with setting up new iptables rules

	// instantitate a watcher and load this watcher instance into self
	ctxWatch, cxlWatch := context.WithCancel(d.ctx)
	d.ctxWatch = ctxWatch
	d.cxlWatch = cxlWatch

	// register the watcher for both nodes and the configmap
	d.watcher.Nodes(ctxWatch, "director-nodes", d.nodeChan)
	d.watcher.ConfigMap(ctxWatch, "director-configmap", d.configChan)

	// perform periodic configuration activities
	go d.periodic()
	go d.watches()
	go d.arps()
	d.logger.Debugf("setup complete. director is running")
	return nil
}

// cleanup sets the initial state of the ipvs director by removing any KUBE-IPVS rules
// from the service chain and by clearing any arp rules that were set by a realserver
// on the same node.
// This function cannot clean up interface configurations, as the interface configurations
// rely on the presence of a config.
func (d *director) cleanup(ctx context.Context) error {
	errs := []string{}
	if err := d.iptables.Flush(); err != nil {
		errs = append(errs, fmt.Sprintf("cleanup - failed to flush iptables - %v", err))
	}

	if err := d.ip.Teardown(ctx); err != nil {
		errs = append(errs, fmt.Sprintf("cleanup - failed to remove ip addresses - %v", err))
	}

	if err := d.ipvs.Teardown(ctx); err != nil {
		errs = append(errs, fmt.Sprintf("cleanup - failed to remove existing ipvs config - %v", err))
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%v", errs)
}

func (d *director) Stop() error {
	if d.reconfiguring {
		return fmt.Errorf("unable to Stop. reconfiguration already in progress.")
	}
	d.setReconfiguring(true)
	defer func() { d.setReconfiguring(false) }()

	// kill the watcher
	d.cxlWatch()
	d.logger.Info("blocking until periodic tasks complete")
	select {
	case <-d.doneChan:
	case <-time.After(5000 * time.Millisecond):
	}

	// remove config VIP addresses from the compute interface
	ctxDestroy, cxl := context.WithTimeout(context.Background(), 5000*time.Millisecond)
	defer cxl()

	if d.doCleanup {
		err := d.cleanup(ctxDestroy)
		d.isStarted = false
		return err
	}

	d.isStarted = false
	return nil
}

func (d *director) Err() error {
	return d.err
}

func (d *director) watches() {
	// XXX This things needs to actually get the list of nodes when a node update occurs
	// XXX It also needs to get all of the endpoints
	// XXX this thing needs a nonblocking, continuous read on the nodes channel and a
	// way to quiesce reads from this channel into actual behaviors in the app...
	for {
		select {

		case nodes := <-d.nodeChan:
			d.logger.Debugf("recv on nodes")
			if types.NodesEqual(d.nodes, nodes, d.logger) {
				d.logger.Debug("NODES ARE EQUAL")
				d.metrics.NodeUpdate("noop")
				continue
			}
			d.metrics.NodeUpdate("updated")
			d.logger.Debug("NODES ARE NOT EQUAL")
			d.Lock()
			d.nodes = nodes

			for _, node := range nodes {
				if node.Name == d.nodeName {
					d.node = node
				}
			}
			d.lastInboundUpdate = time.Now()
			d.Unlock()

		case configs := <-d.configChan:
			d.logger.Debugf("recv on configs")
			d.Lock()
			d.config = configs
			d.newConfig = true
			d.lastInboundUpdate = time.Now()
			d.Unlock()
			d.metrics.ConfigUpdate()

			// Administrative
		case <-d.ctx.Done():
			d.logger.Debugf("parent context closed. exiting run loop")
			return
		case <-d.ctxWatch.Done():
			d.logger.Debugf("watch context closed. exiting run loop")
			return
		}

	}
}

func (d *director) arps() {
	arpInterval := 2000 * time.Millisecond
	gratuitousArp := time.NewTicker(arpInterval)
	defer gratuitousArp.Stop()

	d.logger.Infof("starting periodic ticker. arp interval %v", arpInterval)
	for {
		select {
		case <-gratuitousArp.C:
			// every five minutes or so, walk the whole set of VIPs and make the call to
			// gratuitous arp.
			if d.config == nil || d.nodes == nil {
				d.logger.Debugf("configs are nil. skipping arp clear")
				continue
			}
			ips := []string{}
			d.Lock()
			for ip, _ := range d.config.Config {
				ips = append(ips, string(ip))
			}
			d.Unlock()
			for _, ip := range ips {
				if err := d.ip.AdvertiseMacAddress(ip); err != nil {
					d.metrics.ArpingFailure(err)
					d.logger.Error(err)
				}
			}

		case <-d.ctx.Done():
			d.logger.Debugf("parent context closed. exiting run loop")
			return
		case <-d.ctxWatch.Done():
			d.logger.Debugf("watch context closed. exiting run loop")
			return
		}
	}
}

func (d *director) periodic() {

	// reconfig ipvs
	checkInterval := 100 * time.Millisecond
	t := time.NewTicker(checkInterval)
	d.logger.Infof("starting periodic ticker. config check %v", checkInterval)

	forcedReconfigureInterval := 10 * 60 * time.Second
	forceReconfigure := time.NewTicker(forcedReconfigureInterval)

	defer t.Stop()
	defer forceReconfigure.Stop()

	for {
		select {

		case <-forceReconfigure.C:
			if d.config != nil && d.nodes != nil {
				d.logger.Info("Force reconfiguration w/o parity check timer went off")
				d.reconfigure(true)
			}

		case <-t.C: // periodically apply declared state

			if d.lastReconfigure.Sub(d.lastInboundUpdate) > 0 {
				// Last reconfigure happened after the last update from watcher
				d.logger.Debugf("no changes to configs since last reconfiguration completed")
				continue
			}

			d.metrics.QueueDepth(len(d.configChan))

			if d.config == nil || d.nodes == nil {
				d.logger.Debugf("configs are nil. skipping apply")
				continue
			}

			d.reconfigure(false)

		case <-d.ctx.Done():
			d.logger.Debugf("parent context closed. exiting run loop")
			return
		case <-d.ctxWatch.Done():
			d.logger.Debugf("watch context closed. exiting run loop")
			d.doneChan <- struct{}{}
			return
		}
	}
}

func (d *director) reconfigure(force bool) {
	d.logger.Infof("reconfiguring")
	start := time.Now()
	if err := d.applyConf(force); err != nil {
		d.logger.Errorf("error applying configuration in director. %v", err)
		return
	}
	d.logger.Infof("reconfiguration completed successfully in %v", time.Now().Sub(start))
	d.lastReconfigure = start
}

func (d *director) applyConf(force bool) error {
	// TODO: this thing could have gotten a new copy of nodes by the
	// time it did its thing. need to lock in the caller, capture
	// the current time, deepcopy the nodes/config, and pass them into this.
	d.logger.Debugf("applying configuration")
	start := time.Now()

	// compare configurations and apply them
	if force {
		d.logger.Info("configuration parity ignored")
	} else {
		addresses, _ := d.ip.Get()
		same, err := d.ipvs.CheckConfigParity(d.nodes, d.config, addresses, d.configReady())
		if err != nil {
			d.metrics.Reconfigure("error", time.Now().Sub(start))
			return fmt.Errorf("unable to compare configurations with error %v", err)
		}
		if same {
			d.metrics.Reconfigure("noop", time.Now().Sub(start))
			d.logger.Info("configuration has parity")
			return nil
		}

		d.logger.Info("configuration parity mismatch")
	}

	// Manage VIP addresses
	err := d.setAddresses()
	if err != nil {
		d.metrics.Reconfigure("error", time.Now().Sub(start))
		return fmt.Errorf("unable to configure VIP addresses with error %v", err)
	}
	d.logger.Debugf("addresses set")

	// Manage iptables configuration
	// only execute with cli flag ipvs-colocation-mode=true
	// this indicates the director is in a non-isolated load balancer tier
	if d.colocationMode == colocationModeIPTables {
		err = d.setIPTables()
		if err != nil {
			d.metrics.Reconfigure("error", time.Now().Sub(start))
			return fmt.Errorf("unable to configure iptables with error %v", err)
		}
		d.logger.Debugf("iptables configured")
	}

	// Manage ipvsadm configuration
	err = d.ipvs.SetIPVS(d.nodes, d.config, d.logger)
	if err != nil {
		d.metrics.Reconfigure("error", time.Now().Sub(start))
		return fmt.Errorf("unable to configure ipvs with error %v", err)
	}
	d.logger.Debugf("ipvs configured")

	d.metrics.Reconfigure("complete", time.Now().Sub(start))
	return nil
}

func (d *director) setIPTables() error {

	d.logger.Debugf("capturing iptables rules")
	// generate and apply iptables rules
	existing, err := d.iptables.Save()
	if err != nil {
		return err
	}
	d.logger.Debugf("got %d existing rules", len(existing))

	d.logger.Debugf("generating iptables rules")
	// i need to determine what percentage of traffic should be sent to the master
	// for each namespace/service:port that is in the config, i need to know the proportion
	// of the whole that namespace/service:port represents
	generated, err := d.iptables.GenerateRulesForNodes(d.node, d.config, true)
	if err != nil {
		return err
	}
	d.logger.Debugf("got %d generated rules", len(generated))

	d.logger.Debugf("merging iptables rules")
	merged, _, err := d.iptables.Merge(generated, existing) // subset, all rules
	if err != nil {
		return err
	}
	d.logger.Debugf("got %d merged rules", len(merged))

	d.logger.Debugf("applying updated rules")
	err = d.iptables.Restore(merged)
	if err != nil {
		// write erroneous rule set to file to capture later
		d.logger.Errorf("error applying rules. writing erroneous rule change to /tmp/director-ruleset-err for debugging")
		writeErr := ioutil.WriteFile("/tmp/director-ruleset-err", createErrorLog(err, iptables.BytesFromRules(merged)), 0644)
		if writeErr != nil {
			d.logger.Errorf("error writing to file; logging rules: %s", string(iptables.BytesFromRules(merged)))
		}

		return err
	}

	return nil
}

func (d *director) configReady() bool {
	newConfig := false
	d.Lock()
	if d.newConfig {
		newConfig = true
		d.newConfig = false
	}
	d.Unlock()
	return newConfig
}

func (d *director) setAddresses() error {
	// pull existing
	configured, err := d.ip.Get()
	if err != nil {
		return err
	}

	// get desired VIP addresses
	desired := []string{}
	for ip, _ := range d.config.Config {
		desired = append(desired, string(ip))
	}

	// XXX statsd
	removals, additions := d.ip.Compare(configured, desired)

	for _, addr := range removals {
		d.logger.WithFields(logrus.Fields{"device": "primary", "addr": addr, "action": "deleting"}).Info()
		err := d.ip.Del(addr)
		if err != nil {
			return err
		}
	}
	for _, addr := range additions {
		d.logger.WithFields(logrus.Fields{"device": "primary", "addr": addr, "action": "adding"}).Info()
		if err := d.ip.AdvertiseMacAddress(addr); err != nil {
			d.logger.Warnf("error setting gratuitous arp. this is most likely due to the VIP not being present on the interface. %s", err)
		}
		if err := d.ip.Add(addr); err != nil {
			return err
		}
	}

	return nil
}

func (d *director) setReconfiguring(v bool) {
	d.Lock()
	d.reconfiguring = v
	d.Unlock()
}

func createErrorLog(err error, rules []byte) []byte {
	if err == nil {
		return rules
	}

	errBytes := []byte(fmt.Sprintf("ipvs restore error: %v\n", err.Error()))
	return append(errBytes, rules...)
}
