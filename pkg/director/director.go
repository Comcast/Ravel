package director

import (
	"context"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/Comcast/Ravel/pkg/iptables"
	"github.com/Comcast/Ravel/pkg/stats"
	"github.com/Comcast/Ravel/pkg/system"
	"github.com/Comcast/Ravel/pkg/types"
	"github.com/Comcast/Ravel/pkg/watcher"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

const (
	colocationModeDisabled = "disabled"
	colocationModeIPTables = "iptables"
	colocationModeIPVS     = "ipvs"
)

func init() {
	// uncomment to pin debug logging on
	// log.SetLevel(log.DebugLevel)
}

// TODO: instant startup

type Director struct {
	sync.Mutex

	// start/stop and backpropagation of internal errors
	isStarted bool
	doneChan  chan struct{}
	err       error

	// declarative state - this is what ought to be configured
	nodeName string
	// node     *v1.Node
	// nodes     []*v1.Node
	// config    *types.ClusterConfig
	// newConfig bool

	// inbound data sources
	nodeChan   chan []*v1.Node
	configChan chan *types.ClusterConfig
	ctxWatch   context.Context
	cxlWatch   context.CancelFunc

	reconfiguring bool
	// lastInboundUpdate time.Time
	lastReconfigure time.Time

	watcher   *watcher.Watcher
	ipvs      *system.IPVS
	ipDevices *system.IP
	iptables  *iptables.IPTables

	// cli flag default false
	doCleanup         bool
	colocationMode    string
	forcedReconfigure bool
	// ipvsWeightOverride bool

	// boilerplate.  when this context is canceled, the director must cease all activties
	ctx     context.Context
	logger  log.FieldLogger
	metrics *stats.WorkerStateMetrics
}

func NewDirector(ctx context.Context, nodeName, configKey string, cleanup bool, watcher *watcher.Watcher, ipvs *system.IPVS, ip *system.IP, ipt *iptables.IPTables, colocationMode string, forcedReconfigure bool, logger log.FieldLogger) (*Director, error) {
	d := &Director{
		watcher:   watcher,
		ipvs:      ipvs,
		ipDevices: ip,
		nodeName:  nodeName,

		iptables: ipt,

		doneChan:   make(chan struct{}),
		nodeChan:   make(chan []*v1.Node, 1),
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

func (d *Director) Start() error {
	if d.isStarted {
		return fmt.Errorf("director has already been started. a director instance can only be started once")
	}
	if d.reconfiguring {
		return fmt.Errorf("unable to Start. reconfiguration already in progress")
	}
	d.setReconfiguring(true)
	defer func() { d.setReconfiguring(false) }()
	log.Debugf("director: start called")

	// init
	d.isStarted = true
	d.doneChan = make(chan struct{})

	// set arp rules
	err := d.ipDevices.SetARP()
	if err != nil {
		return fmt.Errorf("director: cleanup - failed to clear arp rules - %v", err)
	}

	if d.colocationMode != colocationModeIPTables {
		// cleanup any lingering iptables rules
		if err := d.iptables.Flush(); err != nil {
			return fmt.Errorf("director: cleanup - failed to flush iptables - %v", err)
		}
	}
	// If director is co-located with a realserver, the realserver
	// will deal with setting up new iptables rules

	// instantitate a watcher and load this watcher instance into self
	ctxWatch, cxlWatch := context.WithCancel(d.ctx)
	d.ctxWatch = ctxWatch
	d.cxlWatch = cxlWatch

	// perform periodic configuration activities
	go d.periodic()
	// go d.watches()
	go d.arps()
	log.Debugf("director: setup complete. director is running")
	return nil
}

// cleanup sets the initial state of the ipvs director by removing any KUBE-IPVS rules
// from the service chain and by clearing any arp rules that were set by a realserver
// on the same node.
// This function cannot clean up interface configurations, as the interface configurations
// rely on the presence of a config.
func (d *Director) cleanup(ctx context.Context) error {
	errs := []string{}
	if err := d.iptables.Flush(); err != nil {
		errs = append(errs, fmt.Sprintf("cleanup - failed to flush iptables - %v", err))
	}

	c4 := d.watcher.ClusterConfig.Config
	c6 := d.watcher.ClusterConfig.Config6

	if err := d.ipDevices.Teardown(ctx, c4, c6); err != nil {
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

func (d *Director) Stop() error {
	if d.reconfiguring {
		return fmt.Errorf("director: unable to Stop. reconfiguration already in progress")
	}
	d.setReconfiguring(true)
	defer func() { d.setReconfiguring(false) }()

	// kill the watcher
	d.cxlWatch()
	log.Info("director: blocking until periodic tasks complete")
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

func (d *Director) Err() error {
	return d.err
}

// func (d *Director) watches() {
// 	log.Debugf("director: starting watches")
// 	// XXX This things needs to actually get the list of nodes when a node update occurs
// 	// XXX It also needs to get all of the endpoints
// 	// XXX this thing needs a nonblocking, continuous read on the nodes channel and a
// 	// way to quiesce reads from this channel into actual behaviors in the app...
// 	for {
// 		log.Debugf("director: starting a watch loop")
// 		select {

// 		case nodes := <-d.nodeChan:
// 			log.Debugf("director: recv on node channel")
// 			if types.NodesEqual(d.nodes, nodes) {
// 				d.metrics.NodeUpdate("noop")
// 				continue
// 			}
// 			d.metrics.NodeUpdate("updated")
// 			d.Lock()
// 			d.nodes = nodes

// 			for _, node := range nodes {
// 				if node.Name == d.nodeName {
// 					d.node = node
// 				}
// 			}
// 			d.lastInboundUpdate = time.Now()
// 			d.Unlock()

// 		case configs := <-d.configChan:
// 			log.Debugf("director: recv on config channel")
// 			d.Lock()
// 			d.config = configs
// 			d.newConfig = true
// 			d.lastInboundUpdate = time.Now()
// 			d.Unlock()
// 			d.metrics.ConfigUpdate()

// 			// Administrative
// 		case <-d.ctx.Done():
// 			log.Debugf("director: parent context closed. exiting run loop")
// 			return
// 		case <-d.ctxWatch.Done():
// 			log.Debugf("director: watch context closed. exiting run loop")
// 			return
// 		}
// 	}
// }

func (d *Director) arps() {
	arpInterval := 2000 * time.Millisecond
	arpTicker := time.NewTicker(arpInterval)
	defer arpTicker.Stop()

	log.Infof("starting periodic ticker. arp interval %v", arpInterval)
	for {
		select {
		case <-arpTicker.C:
			// every five minutes or so, walk the whole set of VIPs and make the call to
			// gratuitous arp.
			if d.watcher.ClusterConfig == nil {
				log.Debugf("configs are nil. skipping arp clear")
				continue
			}
			if d.watcher.Nodes == nil {
				log.Debugf("nodes are nil. skipping arp clear")
				continue
			}

			ips := []string{}
			d.Lock()
			for ip := range d.watcher.ClusterConfig.Config {
				ips = append(ips, string(ip))
			}
			d.Unlock()
			for _, ip := range ips {
				if err := d.ipDevices.AdvertiseMacAddress(ip); err != nil {
					d.metrics.ArpingFailure(err)
					log.Error(err)
				}
			}

		case <-d.ctx.Done():
			log.Debugf("parent context closed. exiting run loop")
			return
		case <-d.ctxWatch.Done():
			log.Debugf("watch context closed. exiting run loop")
			return
		}
	}
}

func (d *Director) periodic() {

	// reconfig ipvs
	checkInterval := time.Second * 3 // reduced by eg 11/9/21
	// checkInterval := 100 * time.Millisecond
	t := time.NewTicker(checkInterval)
	log.Infof("director: periodic: starting periodic ticker. config check %v", checkInterval)

	// forcedReconfigureInterval := 10 * 60 * time.Second
	forcedReconfigureInterval := 10 * time.Second
	forceReconfigure := time.NewTicker(forcedReconfigureInterval)

	defer t.Stop()
	defer forceReconfigure.Stop()

	for {
		// run time debugging
		startTime := time.Now()
		logRunTime := func() {
			runDuration := time.Since(startTime)
			log.Infoln("director: periodic: director iteration took", runDuration)
		}

		select {

		case <-forceReconfigure.C:
			log.Debugf("director: periodic: running forced reconfigure")
			if d.watcher.ClusterConfig.Config != nil || d.watcher.Nodes != nil {
				continue
			}
			log.Info("director: periodic: Force reconfiguration w/o parity check timer went off")
			d.reconfigure(true)
			logRunTime()

		case <-t.C: // periodically apply declared state
			log.Debugf("director: periodic: running reconfigure")

			// if d.lastReconfigure.Before(d.lastInboundUpdate) {
			// 	// Last reconfigure happened after the last update from watcher
			// 	log.Debugf("director: periodic: no changes to configs since last reconfiguration completed")
			// 	logRunTime()
			// 	continue
			// }
			d.metrics.QueueDepth(len(d.configChan))

			if d.watcher.ClusterConfig.Config == nil {
				log.Debugf("director: periodic: d.config is nil. skipping apply")
				logRunTime()
				continue
			}
			if d.watcher.Nodes == nil {
				log.Debugf("director: periodic: d.nodes is nil. skipping apply")
				logRunTime()
				continue
			}

			d.reconfigure(false)
			logRunTime()

		case <-d.ctx.Done():
			log.Debugf("director: periodic: parent context closed. exiting run loop")
			logRunTime()
			log.Info("director: periodic: director periodic loop exiting gracefully due to context cancellation")
			return
		case <-d.ctxWatch.Done():
			log.Debugf("director: periodic: watch context closed. exiting run loop")
			d.doneChan <- struct{}{}
			logRunTime()
			log.Info("director: periodic: director periodic loop exiting gracefully due to watch context cancellation")
			return
		}

		logRunTime()
	}
}

func (d *Director) reconfigure(force bool) {
	log.Infof("director: reconfiguring")
	start := time.Now()
	if err := d.applyConf(force); err != nil {
		log.Errorf("error applying configuration in director. %v", err)
		return
	}
	log.Infof("director: reconfiguration completed successfully in %v", time.Since(start))
	d.lastReconfigure = start
}

func (d *Director) applyConf(force bool) error {
	// TODO: this thing could have gotten a new copy of nodes by the
	// time it did its thing. need to lock in the caller, capture
	// the current time, deepcopy the nodes/config, and pass them into this.
	log.Debugf("director: applying configuration")
	start := time.Now()

	// compare configurations and apply them
	if !force {
		log.Infoln("director: fetching dummy interfaces via director applyConf")
		addressesV4, addressesV6, err := d.ipDevices.Get()
		if err != nil {
			d.metrics.Reconfigure("error", time.Since(start))
			return fmt.Errorf("unable to get v4, v6 addrs: saw error %v", err)
		}

		// splice together to compare against the internal state of configs
		// addresses is sorted within the CheckConfigParity function
		addresses := append(addressesV4, addressesV6...)
		log.Debugln("director: CheckConfigParity: director passing in these addresses:", addresses)

		same, err := d.ipvs.CheckConfigParity(d.watcher, d.watcher.ClusterConfig, addresses)
		if err != nil {
			d.metrics.Reconfigure("error", time.Since(start))
			return fmt.Errorf("unable to compare configurations with error %v", err)
		}
		if same {
			d.metrics.Reconfigure("noop", time.Since(start))
			log.Infoln("director: configuration has parity")
			return nil
		}

		log.Infoln("director: configuration parity mismatch")
	}

	// Manage VIP addresses
	err := d.setAddresses()
	if err != nil {
		d.metrics.Reconfigure("error", time.Since(start))
		return fmt.Errorf("unable to configure VIP addresses with error %v", err)
	}
	log.Debugln("director: VIP addresses set successfully")

	// Manage iptables configuration
	// only execute with cli flag ipvs-colocation-mode=true
	// this indicates the director is in a non-isolated load balancer tier
	if d.colocationMode == colocationModeIPTables {
		err = d.setIPTables()
		if err != nil {
			d.metrics.Reconfigure("error", time.Since(start))
			return fmt.Errorf("unable to configure iptables with error %v", err)
		}
		log.Debugln("director: iptables configured")
	}

	// Manage ipvsadm configuration
	log.Debugln("director: ipvs commands being set")
	err = d.ipvs.SetIPVS(d.watcher, d.watcher.ClusterConfig, d.logger)
	if err != nil {
		d.metrics.Reconfigure("error", time.Since(start))
		return fmt.Errorf("unable to configure ipvs with error %v", err)
	}
	log.Debugln("director: ipvs configured")

	d.metrics.Reconfigure("complete", time.Since(start))
	return nil
}

func (d *Director) setIPTables() error {
	if d.nodeName == "" {
		return fmt.Errorf("director: can not setIPTables because nodeName is blank")
	}

	log.Debugf("director: capturing iptables rules")
	// generate and apply iptables rules
	existing, err := d.iptables.Save()
	if err != nil {
		return err
	}
	log.Debugf("director: got %d existing rules", len(existing))

	log.Debugf("director: generating iptables rules")
	// i need to determine what percentage of traffic should be sent to the master
	// for each namespace/service:port that is in the config, i need to know the proportion
	// of the whole that namespace/service:port represents
	generated, err := d.iptables.GenerateRulesForNode(d.watcher, d.nodeName, d.watcher.ClusterConfig, true)
	if err != nil {
		return err
	}
	log.Debugf("director: got %d generated rules", len(generated))

	log.Debugf("director: merging iptables rules")
	merged, _, err := d.iptables.Merge(generated, existing) // subset, all rules
	if err != nil {
		return err
	}
	log.Debugf("director: got %d merged rules", len(merged))

	log.Debugf("director: applying updated rules")
	err = d.iptables.Restore(merged)
	if err != nil {
		// set our failure gauge for iptables alertmanagers
		d.metrics.IptablesWriteFailure(1)
		// write erroneous rule set to file to capture later
		log.Errorf("director: error applying rules. writing erroneous rule change to /tmp/director-ruleset-err for debugging")
		writeErr := ioutil.WriteFile("/tmp/director-ruleset-err", createErrorLog(err, iptables.BytesFromRules(merged)), 0644)
		if writeErr != nil {
			log.Errorf("director: error writing to file; logging rules: %s", string(iptables.BytesFromRules(merged)))
		}

		return err
	}

	// set gauge to success
	d.metrics.IptablesWriteFailure(0)
	return nil
}

// func (d *Director) configReady() bool {
// 	newConfig := false
// 	d.Lock()
// 	if d.newConfig {
// 		newConfig = true
// 		d.newConfig = false
// 	}
// 	d.Unlock()
// 	return newConfig
// }

func (d *Director) setAddresses() error {
	log.Infoln("director: fetching dummy interfaces via director setAddresses")

	// pull existing
	configuredV4, _, err := d.ipDevices.Get()
	if err != nil {
		return err
	}

	// get desired VIP addresses
	desired := []string{}
	for ip := range d.watcher.ClusterConfig.Config {
		desired = append(desired, string(ip))
	}

	// compare and remove v4 addresses
	removals, additions := d.ipDevices.Compare4(configuredV4, desired)
	for _, addr := range removals {
		log.Debugln("director: removing dummy adapter IP", addr)
		// log.WithFields(log.Fields{"device": "primary", "addr": addr, "action": "deleting"}).Info()
		err := d.ipDevices.Del(addr)
		if err != nil {
			return err
		}
	}

	for _, addr := range additions {
		// log.WithFields(log.Fields{"device": "primary", "addr": addr, "action": "adding"}).Info()
		log.Debugln("director: adding dummy adapter IP", addr)
		if err := d.ipDevices.Add(addr); err != nil {
			return err
		}

		if err := d.ipDevices.AdvertiseMacAddress(addr); err != nil {
			log.Warnf("error setting gratuitous arp. %s", err)
		}
	}

	// now iterate across configured and see if we have a non-standard MTU
	// setting it where applicable
	err = d.ipDevices.SetMTU(d.watcher.ClusterConfig.MTUConfig, false)
	if err != nil {
		return err
	}

	return nil
}

func (d *Director) setReconfiguring(v bool) {
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
