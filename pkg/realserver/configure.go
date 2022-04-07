package realserver

import (
	"context"
	"fmt"
	"io/ioutil"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Comcast/Ravel/pkg/haproxy"
	"github.com/Comcast/Ravel/pkg/iptables"
	"github.com/Comcast/Ravel/pkg/stats"
	"github.com/Comcast/Ravel/pkg/system"
	"github.com/Comcast/Ravel/pkg/watcher"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

// RealServer describes the interface required for a realserver
type RealServer interface {
	Start() error
	Stop() error
}

// TODO - remove
func init() {
	log.SetLevel(log.DebugLevel)
}

// realserver is responsible for managing iptables
type realserver struct {
	sync.Mutex

	// haproxy configs
	haproxy haproxy.HAProxySet

	watcher   *watcher.Watcher
	ipPrimary *system.IP
	ipDevices *system.IP
	ipvs      *system.IPVS
	iptables  *iptables.IPTables

	nodeName string

	doneChan chan struct{}

	// config *types.ClusterConfig
	// configChan chan *types.ClusterConfig
	// node       *v1.Node
	// nodeChan   chan []*v1.Node
	cxlWatch context.CancelFunc
	ctxWatch context.Context

	reconfiguring     bool
	lastInboundUpdate time.Time
	lastReconfigure   time.Time
	forcedReconfigure bool

	ctx     context.Context
	logger  log.FieldLogger
	metrics *stats.WorkerStateMetrics
}

// NewRealServer creates a new realserver
func NewRealServer(ctx context.Context, nodeName string, configKey string, watcher *watcher.Watcher, ipPrimary *system.IP, ipDevices *system.IP, ipvs *system.IPVS, ipt *iptables.IPTables, forcedReconfigure bool, haproxy *haproxy.HAProxySetManager, logger log.FieldLogger) (RealServer, error) {
	return &realserver{
		watcher:   watcher,
		ipPrimary: ipPrimary,
		ipDevices: ipDevices,
		ipvs:      ipvs,
		iptables:  ipt,
		nodeName:  nodeName,

		haproxy: haproxy,

		doneChan: make(chan struct{}),
		// configChan: make(chan *types.ClusterConfig, 1),
		// nodeChan:   make(chan []*v1.Node, 1),

		ctx:               ctx,
		logger:            logger,
		metrics:           stats.NewWorkerStateMetrics(stats.KindRealServer, configKey),
		forcedReconfigure: forcedReconfigure,
	}, nil
}

// Stop stops the realserver tickers that configure and true up iptables
// TODO: IN THIS CASE STOP CAN BE CALLED WITHOUT THE CANCEL FUNCTION. . WELP DAY
func (r *realserver) Stop() error {
	if r.reconfiguring {
		return fmt.Errorf("unable to stop. reconfiguration already in progress")
	}
	r.setReconfiguring(true)
	defer func() { r.setReconfiguring(false) }()

	// This is a little different from the BGP approach. Because the load balancer
	// can be stopped and restarted, we use the cxlWatch context to determine whether
	// the periodic task is complete.
	if r.cxlWatch != nil {
		r.cxlWatch()
	}
	r.logger.Info("blocking until periodic tasks complete")
	select {
	case <-r.doneChan:
	case <-time.After(5000 * time.Millisecond):
	}
	// remove config VIP addresses from the compute interface
	ctxDestroy, cxl := context.WithTimeout(context.Background(), 5000*time.Millisecond)
	defer cxl()

	r.logger.Info("starting cleanup")
	err := r.cleanup(ctxDestroy)
	r.logger.Infof("cleanup complete. error=%v", err)
	return err
}

// cleanup removes all iptables deviecs and flushes rules for clean shutdown
func (r *realserver) cleanup(ctx context.Context) error {
	errs := []string{}

	// delete all k2i addresses from loopback
	if r.watcher.ClusterConfig != nil {
		if err := r.ipDevices.Teardown(ctx, r.watcher.ClusterConfig.Config, r.watcher.ClusterConfig.Config6); err != nil {
			errs = append(errs, fmt.Sprintf("cleanup - failed to remove ip addresses - %v", err))
		}
	}

	// flush iptables
	if err := r.iptables.Flush(); err != nil {
		errs = append(errs, fmt.Sprintf("cleanup - failed to flush iptables - %v", err))
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%v", errs)
}

// setup cleans the node and then prepares iptables for further vip-specific configuration
func (r *realserver) setup() error {
	var err error

	// run cleanup
	err = r.cleanup(r.ctx)
	if err != nil {
		return err
	}

	// set arp rules on loopback
	// NOTE: this call absolutely must follow the cleanup call.
	// If ARP rules are set before cleanup occurs, we may inadvertently publish ownership of an IP address to a router
	err = r.ipDevices.SetARP()
	if err != nil {
		return err
	}
	err = r.ipDevices.SetRPFilter()
	if err != nil {
		return err
	}
	err = r.ipPrimary.SetARP()
	if err != nil {
		return err
	}

	// load this watcher instance into self
	ctxWatch, cxlWatch := context.WithCancel(r.ctx)
	r.ctxWatch = ctxWatch
	r.cxlWatch = cxlWatch

	return nil
}

func (r *realserver) setReconfiguring(v bool) {
	r.Lock()
	r.reconfiguring = v
	r.Unlock()
}

// Start begins realserver operations in the background on tickers
func (r *realserver) Start() error {
	r.logger.Info("Enter Start()")
	defer r.logger.Info("Exit Start()")
	if r.reconfiguring {
		return fmt.Errorf("realserver: unable to start: reconfiguration already in progress")
	}
	r.setReconfiguring(true)
	defer func() { r.setReconfiguring(false) }()

	err := r.setup()
	if err != nil {
		return err
	}

	go r.periodic()
	// go r.watches()

	return nil
}

// // watches starts the various watches required to keep things up to date, such as
// // watching for nodes to be added or removed
// func (r *realserver) watches() {

// 	for {
// 		select {

// 		case nodes := <-r.nodeChan:
// 			r.logger.Debugf("realserver: recv on nodes, %d in list", len(nodes))
// 			var node *v1.Node
// 			found := false
// 			for _, n := range nodes {

// 				r.logger.Debugf("realserver: Name: %s, nodeName %s, equals %v", n.Name, r.nodeName, n.Name == r.nodeName)
// 				if n.Name == r.nodeName {
// 					node = n
// 					found = true
// 					break
// 				}
// 			}

// 			if !found {
// 				r.logger.Infof("realserver: node named %s not found, this shouldn't happen.", r.nodeName)
// 				continue
// 			}

// 			// filter list of nodes to just _my_ node.
// 			if types.NodeEqual(r.node, node) {
// 				r.metrics.NodeUpdate("noop")
// 				continue
// 			}
// 			r.metrics.NodeUpdate("updated")
// 			r.Lock()
// 			r.node = node
// 			r.lastInboundUpdate = time.Now()
// 			r.Unlock()
// 			r.logger.Infof("realserver: watches: new node set on ralserver.node:", node)

// 		case config := <-r.configChan:
// 			// every time a new config kicks in, check parity and apply
// 			r.logger.Infof("realserver: recv on config: %+v", config)
// 			r.Lock()
// 			r.config = config
// 			r.lastInboundUpdate = time.Now()
// 			r.Unlock()
// 			r.metrics.ConfigUpdate()

// 		}
// 	}

// }

// This function is the meat of the realserver struct. ALL CHANGES MADE HERE MUST BE MIRRORED IN pkg/bgp/worker.go
func (r *realserver) periodic() error {

	adapterTicker := time.NewTicker(time.Second * 10)
	defer adapterTicker.Stop()

	// checkTimer ticks reprse
	checkTicker := time.NewTicker(3 * time.Second)
	defer checkTicker.Stop()

	forcedReconfigureInterval := time.Minute * 10
	forceReconfigure := time.NewTicker(forcedReconfigureInterval)
	defer forceReconfigure.Stop()

	for {
		select {
		// if a force reconfigure happens, we do this
		case <-forceReconfigure.C:
			if r.forcedReconfigure {
				/*
					note on error fall through: configure and configure6 are similar,
					but different configuration efforts. I don't see why we would
					ever _not_ want to attempt a config6() call if config() fails,
					with the reasoning that a potentially partial working state is
					better than giving up

					However, if we fail to configure6(), new haproxy calls will fail
					with error to start haproxy. For that reason, we continue
					in that error block
				*/
				start := time.Now()
				r.logger.Info("realserver: forced reconfigure, not performing parity check")
				if err, _ := r.configure(); err != nil {
					r.logger.Errorf("realserver: unable to apply ipv4 configuration, %v", err)
					r.metrics.Reconfigure("error", time.Since(start))
				}

				if err, _ := r.configure6(); err != nil {
					r.logger.Errorf("realserver: unable to apply ipv6 configuration, %v", err)
					r.metrics.Reconfigure("error", time.Since(start))
					continue // new haproxies will fail if this block fails. see note above on continue statements
				}

				// configure haproxy for v6-v4 NAT gateway
				err := r.ConfigureHAProxy()
				if err != nil {
					r.logger.Errorf("realserver: error applying haproxy config in realserver. %v", err)
					r.metrics.Reconfigure("error", time.Since(start))
					continue
				}

				now := time.Now()
				r.logger.Infof("realserver: reconfiguration completed successfully in %v", now.Sub(start))
				r.lastReconfigure = start

				r.metrics.Reconfigure("complete", time.Since(start))
			}

		// check config parity every time this ticks and configure haproxy for NAT gateway support
		case <-adapterTicker.C:

			start := time.Now()
			r.logger.Infof("realserver: reconfig triggered due to periodic parity check")
			same, err := r.checkConfigParity()
			if err != nil {
				// what is a better way to handle this scenario?
				r.logger.Errorf("realserver: parity check failed. %v", err)
				continue
			}
			if same {
				// noop
				r.logger.Debugf("realserver: configuration has parity")
				continue
			}
			r.logger.Debugf("realserver: configuration needs updated")

			if err, _ := r.configure(); err != nil {
				r.metrics.Reconfigure("error", time.Since(start))
				r.logger.Errorf("realserver: unable to apply ipv4 configuration, %v", err)
			}

			if err, _ := r.configure6(); err != nil {
				r.metrics.Reconfigure("error", time.Since(start))
				r.logger.Errorf("realserver: unable to apply ipv6 configuration, %v", err)
				continue // new haproxies will fail if this block fails. see note above on continue statements
			}

			// configure haproxy for v6-v4 NAT gateway
			err = r.ConfigureHAProxy()
			if err != nil {
				r.logger.Errorf("realserver: error applying haproxy config in realserver. %v", err)
				r.metrics.Reconfigure("error", time.Since(start))
				continue
			}

			now := time.Now()
			r.logger.Infof("realserver: reconfiguration completed successfully in %v", now.Sub(start))
			r.lastReconfigure = start

			r.metrics.Reconfigure("complete", time.Since(start))

		// every time this ticks, we reconfigure all iptables rules and check config parity
		case <-checkTicker.C:
			start := time.Now()
			// TODO: add metrics back in!

			// If there's nothing to do, there's nothing to do.
			r.logger.Debugf("realserver: reconfig math lastReconfigure=%v lastInboundUpdate=%v subtr=%v cond=%v",
				r.lastReconfigure,
				r.lastInboundUpdate,
				r.lastReconfigure.Sub(r.lastInboundUpdate),
				r.lastReconfigure.Sub(r.lastInboundUpdate) > 0)
			if r.lastReconfigure.Sub(r.lastInboundUpdate) > 0 {
				// No noop metric here - we only noop if a non-impactful config change makes it through
				r.logger.Debugf("realserver: no changes to configs since last reconfiguration completed")
				continue
			}

			// r.metrics.QueueDepth(len(r.configChan))

			if r.watcher.ClusterConfig == nil {
				log.Warningln("realserver: can not check parity because config is nil")
				r.metrics.Reconfigure("noop", time.Since(start))
				continue
			}
			if r.nodeName == "" {
				log.Errorln("realserver: can not check parity because nodeName is not set")
				r.metrics.Reconfigure("noop", time.Since(start))
				continue
			}

			log.Debugln("realserver: checking configuration parity")
			same, err := r.checkConfigParity()
			if err != nil {
				// what is a better way to handle this scenario?
				r.logger.Errorf("realserver: parity check failed. %v", err)
				continue
			} else if same {
				// noop
				r.logger.Debugf("realserver: configuration has parity")
				continue
			}

			err, _ = r.configure()
			if err != nil {
				r.logger.Errorf("realserver: error applying configuration in realserver. %v", err)
				r.metrics.Reconfigure("error", time.Since(start))
			}

			if err, _ = r.configure6(); err != nil {
				r.metrics.Reconfigure("error", time.Since(start))
				r.logger.Errorf("realserver: unable to apply ipv6 configuration, %v", err)
				continue // new haproxies will fail if this block fails. see note above on continue statements
			}

			// configure haproxy for v6-v4 NAT gateway
			err = r.ConfigureHAProxy()
			if err != nil {
				r.logger.Errorf("realserver: error applying haproxy config in realserver. %v", err)
				r.metrics.Reconfigure("error", time.Since(start))
				continue
			}

			now := time.Now()
			r.logger.Infof("realserver: reconfiguration completed successfully in %v", now.Sub(start))
			r.lastReconfigure = start

			r.metrics.Reconfigure("complete", time.Since(start))

		case <-r.ctx.Done():
			return nil
		case <-r.ctxWatch.Done():
			r.doneChan <- struct{}{}
			return nil
		}

	}
}

// ConfigureHAProxy uses haproxy as a bridge between a v6 address and a v4
// pod address. This function iterates over the declared v6 configs and backends
// for each, checks if any pods match that service selector, and creates a
// haproxy instance for each backend that maps the VIP:PORT to a list of backend
// these are the pod ips, not the service IPs, to ensure traffic stays on-node
// creates 1 config - per - ipv6addr + port pair
func (r *realserver) ConfigureHAProxy() error {

	// measure the time it took to do this operation
	configureStartTime := time.Now()
	defer func() {
		configureDuration := time.Since(configureStartTime)
		log.Println("realserver: HAProxy configuration took", configureDuration)
	}()

	configSet := []haproxy.VIPConfig{}
	for ip, config := range r.watcher.ClusterConfig.Config6 {
		// make a single haproxy server for each v6 VIP with all backends
		for port, service := range config {

			mtu := r.watcher.ClusterConfig.MTUConfig6[ip]

			// fetch the service config and pluck the clusterIP
			if !r.watcher.ServiceHasValidEndpoints(service.Namespace, service.Service) {
				r.logger.Warnf("realserver: no service found for configuration [%s]:(%s/%s), skipping haproxy config", string(ip), service.Namespace, service.Service)
				continue
			}

			// skip if node is empty
			if r.nodeName == "" {
				log.Warningln("realserver: can not get pod IPs for node because node is blank")
				continue
			}
			ips := r.watcher.GetPodIPsOnNode(r.nodeName, service.Service, service.Namespace, service.PortName)
			services := r.watcher.Services()
			serviceName := fmt.Sprintf("%s/%s", service.Namespace, service.Service)
			serviceForConfig, ok := services[serviceName]
			if !ok {
				log.Warnln("realserver: services map held no service with serviceName %s", serviceName)
				continue
			}
			if service == nil {
				log.Warnln("realserver: error creating haproxy configs. Could not find kube service %s on ip [%s]", serviceName, string(ip))
				continue
			}
			if serviceForConfig == nil {
				log.Warnln("realserver: serviceForConfig was nil.  Could not find a service with the name", serviceName)
				continue
			}
			if ips == nil {
				log.Warnln("realserver: pod ips were nil for service", service.Service, "in namespace", service.Namespace, "using port name", service.PortName)
				continue
			}
			if serviceForConfig.Spec.Ports == nil {
				log.Warnln("realserver: ports were nil for service", service.Service, "in namespace", service.Namespace, "using port name", service.PortName)
				continue
			}

			// iterate over service ports and retrieve the one we want for this config
			// we search for targetPort, the actual port open on the pod IP on this node
			// recall that we are searching for the port that is open on the pod
			// NOT the port on the config, and not even necessarily the service port
			// because kube can map a service port to a target port, or they are the same
			var targetPortForService string
			for _, servicePort := range serviceForConfig.Spec.Ports {
				if service.Service == serviceForConfig.Name {
					targetPortForService = retrieveTargetPort(servicePort)
					break
				}
			}

			sort.Strings(ips)
			haConfig := haproxy.VIPConfig{
				Addr6:       string(ip),
				PodIPs:      ips,
				TargetPort:  targetPortForService,
				MTU:         mtu,
				ServicePort: port,
			}
			// guard against initializing watcher race condition and haproxy
			// panics from 0-len lists
			if haConfig.IsValid() {
				r.logger.Debugf("realserver: adding haproxy config for ipv6: %+v", haConfig)
				configSet = append(configSet, haConfig)
			}
		}
	}

	r.logger.Infof("realserver: got %d haproxy addresses to set", len(configSet))

	validSet := []string{}
	for _, cs := range configSet {
		if err := r.haproxy.Configure(cs); err != nil {
			return err
		}

		// create the new set of valid configurations
		validSet = append(validSet, fmt.Sprintf("%s:%s", cs.Addr6, cs.ServicePort))
	}

	// then get items to be removed
	removalSet := r.haproxy.GetRemovals(validSet)
	for _, addr := range removalSet {
		r.logger.Infof("realserver: halting pruned haproxy instance %s", addr)
		r.haproxy.StopOne(addr)
	}

	return nil
}

// configure applies the desired realserver configuration to iptables
func (r *realserver) configure() (error, int) {
	if r.watcher.ClusterConfig == nil {
		return fmt.Errorf("realserver: could not configure. cluster config is nil"), 0
	}

	// log the services that exist for this node at the start of rule generation
	services := []string{}
	for _, portMap := range r.watcher.ClusterConfig.Config {
		for _, sc := range portMap {
			services = append(services, sc.Namespace+"/"+sc.Service+":"+sc.PortName)
		}
	}
	log.Debugln("realserver: configure: running for", len(r.watcher.ClusterConfig.Config), "service IPs hosting", len(services), "services total:", strings.Join(services, ","))

	// log the duration of time it took to do the reconfiguration
	configureStartTime := time.Now()
	defer func() {
		configureDuration := time.Since(configureStartTime)
		r.logger.Infoln("realserver: IPVS reconfiguration took", configureDuration)
	}()

	removals := 0
	r.logger.Debugf("realserver: setting addresses")
	// add vip addresses to loopback
	if err := r.setAddresses(); err != nil {
		return err, removals
	}

	r.logger.Debugf("realserver: capturing iptables rules")
	// generate and apply iptables rules
	existing, err := r.iptables.Save()
	if err != nil {
		return err, removals
	}
	r.logger.Debugf("realserver: got %d existing rules", len(existing))

	// r.logger.Debugf("generating iptables rules")
	// generate desired iptables configurations
	// generated, err := r.iptables.GenerateRules(r.watcher.ClusterConfig)
	generated, err := r.iptables.GenerateRulesForNode(r.watcher, r.nodeName, r.watcher.ClusterConfig, false)
	if err != nil {
		return err, removals
	}
	r.logger.Debugf("realserver: got %d generated rules", len(generated))

	r.logger.Debugf("realserver: merging iptables rules")
	merged, removals, err := r.iptables.Merge(generated, existing) // subset, all rules
	if err != nil {
		return err, removals
	}
	r.logger.Debugf("realserver: got %d merged rules", len(merged))

	// r.logger.Debugf("applying updated rules")
	err = r.iptables.Restore(merged)
	if err != nil {
		// set our failure gauge for iptables alertmanagers
		r.metrics.IptablesWriteFailure(1)
		// write erroneous rule set to file to capture later
		r.logger.Errorf("realserver: error applying rules. writing erroneous rule change to /tmp/realserver-ruleset-err for debugging")
		writeErr := ioutil.WriteFile("/tmp/realserver-ruleset-err", createErrorLog(err, iptables.BytesFromRules(merged)), 0644)
		if writeErr != nil {
			r.logger.Errorf("realserver: error writing to file; logging rules: %s", string(iptables.BytesFromRules(merged)))
		}

		return err, removals
	}

	// set gauge to success
	r.metrics.IptablesWriteFailure(0)

	return nil, removals
}

// configure6 configures the HAProxy deployment for ipv4 to ipv6 translation.
// We omit iptables rules here, set v6 addresses on loopback
func (r *realserver) configure6() (error, int) {

	removals := 0
	// add vip addresses to loopback
	if err := r.setAddresses6(); err != nil {
		return err, removals
	}
	return nil, removals
}

// checkConfigParity checks all the dummy interfaces and ensures that they are
// properly configured and applied to iptables chains
func (r *realserver) checkConfigParity() (bool, error) {

	// =======================================================
	// == Perform check whether we're ready to start working
	// =======================================================
	if r.watcher.ClusterConfig == nil {
		return true, nil
	}

	// =======================================================
	// == Perform check on ethernet device configuration
	// =======================================================
	// pull existing eth configurations
	log.Infoln("realserver: fetching dummy interfaces via checkConfigParity")
	addressesV4, addressesV6, err := r.ipDevices.Get()
	if err != nil {
		return false, err
	}

	// get desired set of VIP addresses
	vipsV4 := []string{}
	for ip := range r.watcher.ClusterConfig.Config {
		vipsV4 = append(vipsV4, string(ip))
	}
	sort.Strings(vipsV4)

	// and, v6 addresses
	vipsV6 := []string{}
	for ip := range r.watcher.ClusterConfig.Config6 {
		vipsV6 = append(vipsV6, string(ip))
	}
	sort.Strings(vipsV6)

	// =======================================================
	// == Perform check on iptables configuration
	// =======================================================
	// pull existing iptables configurations
	existing, err := r.iptables.Save()
	if err != nil {
		return false, err
	}
	existingRules := []string{}
	if k, found := existing[r.iptables.BaseChain()]; found { // XXX table name must be configurable
		existingRules = k.Rules
		sort.Strings(existingRules)
	}

	// TODO: Why not this? Why cluster config was changed do we do it in two different ways
	// generated, err := r.iptables.GenerateRulesForNode(r.node, r.config, false)

	// generate desired iptables configurations
	generated, err := r.iptables.GenerateRules(r.watcher.ClusterConfig)
	if err != nil {
		return false, err
	}

	generatedRules := generated[r.iptables.BaseChain()].Rules
	sort.Strings(generatedRules)
	log.Debugln("realserver: checkConfigParity: generated", len(generatedRules), "rules")

	// TODO: check haproxy config parity? updates are forced on changes
	// to the endpoints list. A v6 address on loopback is indicative of
	// a successful config6() unless early exit

	// compare and return
	if reflect.DeepEqual(vipsV4, addressesV4) &&
		reflect.DeepEqual(vipsV6, addressesV6) &&
		reflect.DeepEqual(existingRules, generatedRules) {
		log.Debugln("realserver: checkConfigParity: configured rules match generated rules")
		return true, nil
	}
	log.Debugln("realserver: checkConfigParity: configured rules DO NOT match generated rules")
	return false, nil
}

// setAddresses sets all the VIP addresses into iptables along with the proper MTUs
func (r *realserver) setAddresses() error {

	log.Infoln("fetching dummy interfaces via realserver setAddresses")

	// pull existing
	configuredv4, _, err := r.ipDevices.Get()
	if err != nil {
		return err
	}

	// get desired set VIP addresses
	desired := []string{}
	devToAddr := map[string]string{}
	for ip := range r.watcher.ClusterConfig.Config {
		devName := r.ipDevices.Device(string(ip), false)
		desired = append(desired, devName)
		devToAddr[devName] = string(ip)
	}

	removals, additions := r.ipDevices.Compare4(configuredv4, desired)
	for _, device := range removals {
		// r.logger.WithFields(logrus.Fields{"device": device, "action": "deleting"}).Info()
		err := r.ipDevices.Del(device)
		if err != nil {
			return err
		}
	}

	for _, device := range additions {
		addr := devToAddr[device]
		// r.logger.WithFields(logrus.Fields{"device": device, "addr": addr, "action": "adding"}).Info()
		err := r.ipDevices.Add(addr)
		if err != nil {
			return err
		}
	}

	// now iterate across configured and see if we have a non-standard MTU
	// setting it where applicable
	// pull existing
	err = r.ipDevices.SetMTU(r.watcher.ClusterConfig.MTUConfig, false)
	if err != nil {
		return err
	}

	return nil
}

// setAddresses6 adds ipv6 virtual network devices to iptables and removes any
// that should not exist
func (r *realserver) setAddresses6() error {
	// log.Infoln("fetching dummy interfaces via realserver setAddresses6")

	// pull existing
	_, configuredV6, err := r.ipDevices.Get()
	if err != nil {
		return err
	}

	// get desired set VIP addresses
	desired := []string{}
	devToAddr := map[string]string{}
	for ip := range r.watcher.ClusterConfig.Config6 {
		devName := r.ipDevices.Device(string(ip), true)
		desired = append(desired, devName)
		devToAddr[devName] = string(ip)
	}

	removals, additions := r.ipDevices.Compare6(configuredV6, desired)
	for _, device := range removals {
		// r.logger.WithFields(logrus.Fields{"device": device, "action": "deleting"}).Info()
		err := r.ipDevices.Del(device)
		if err != nil {
			return err
		}
	}

	for _, device := range additions {
		addr := devToAddr[device]

		// r.logger.WithFields(logrus.Fields{"device": device, "addr": addr, "action": "adding"}).Info()
		err := r.ipDevices.Add6(addr)
		if err != nil {
			return err
		}
	}

	// now iterate across configured and see if we have a non-standard MTU
	// setting it where applicable
	// pull existing
	err = r.ipDevices.SetMTU(r.watcher.ClusterConfig.MTUConfig6, true)
	if err != nil {
		return err
	}

	return nil
}

func createErrorLog(err error, rules []byte) []byte {
	if err == nil {
		return rules
	}

	errBytes := []byte(fmt.Sprintf("ipvs restore error: %v\n", err.Error()))
	return append(errBytes, rules...)
}

func retrieveTargetPort(servicePort v1.ServicePort) string {
	/*
		this is an annoying kube type IntOrString, so we have to
		decide which it is and then set it as uint16 here
		additionally if targetport is not defined, targetPort == port:

		kube docs: "Note: A Service can map any incoming port to a targetPort.
		By default and for convenience, the targetPort is set to the same value as the port field."

		This case is our third check here
	*/
	if servicePort.TargetPort.StrVal != "" {
		return servicePort.TargetPort.StrVal
	} else if servicePort.TargetPort.IntVal != 0 {
		return strconv.Itoa(int(servicePort.TargetPort.IntVal))
	} else {
		// targetPort == port
		return string(servicePort.Port)
	}
}
