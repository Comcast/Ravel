package realserver

import (
	"context"
	"fmt"
	"io/ioutil"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/comcast/ravel/pkg/haproxy"
	"github.com/comcast/ravel/pkg/iptables"
	"github.com/comcast/ravel/pkg/stats"
	"github.com/comcast/ravel/pkg/system"
	"github.com/comcast/ravel/pkg/types"
)

type RealServer interface {
	Start() error
	Stop() error
}

type realserver struct {
	sync.Mutex

	// haproxy configs
	haproxy haproxy.HAProxySet

	watcher    system.Watcher
	ipPrimary  system.IP
	ipLoopback system.IP
	ipvs       system.IPVS
	iptables   iptables.IPTables

	nodeName string

	doneChan chan struct{}
	err      error

	config     *types.ClusterConfig
	configChan chan *types.ClusterConfig
	node       types.Node
	nodeChan   chan types.NodesList
	cxlWatch   context.CancelFunc
	ctxWatch   context.Context

	reconfiguring     bool
	lastInboundUpdate time.Time
	lastReconfigure   time.Time
	forcedReconfigure bool

	ctx     context.Context
	logger  logrus.FieldLogger
	metrics *stats.WorkerStateMetrics
}

func NewRealServer(ctx context.Context, nodeName string, configKey string, watcher system.Watcher, ipPrimary system.IP, ipLoopback system.IP, ipvs system.IPVS, ipt iptables.IPTables, forcedReconfigure bool, logger logrus.FieldLogger) (RealServer, error) {
	haproxy := haproxy.NewHAProxySet(ctx, "/usr/sbin/haproxy", "/etc/ravel", logger)
	return &realserver{
		watcher:    watcher,
		ipPrimary:  ipPrimary,
		ipLoopback: ipLoopback,
		ipvs:       ipvs,
		iptables:   ipt,
		nodeName:   nodeName,

		haproxy: haproxy,

		doneChan:   make(chan struct{}),
		configChan: make(chan *types.ClusterConfig, 1),
		nodeChan:   make(chan types.NodesList, 1),

		ctx:               ctx,
		logger:            logger,
		metrics:           stats.NewWorkerStateMetrics(stats.KindRealServer, configKey),
		forcedReconfigure: forcedReconfigure,
	}, nil
}

// TODO: IN THIS CASE STOP CAN BE CALLED WITHOUT THE CANCEL FUNCTION. . WELP DAY
func (r *realserver) Stop() error {
	if r.reconfiguring {
		return fmt.Errorf("unable to Stop. reconfiguration already in progress.")
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

func (r *realserver) cleanup(ctx context.Context) error {
	errs := []string{}

	// delete all k2i addresses from loopback
	if err := r.ipLoopback.Teardown(ctx); err != nil {
		errs = append(errs, fmt.Sprintf("cleanup - failed to remove ip addresses - %v", err))
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
	err = r.ipLoopback.SetARP()
	if err != nil {
		return err
	}
	err = r.ipLoopback.SetRPFilter()
	if err != nil {
		return err
	}
	err = r.ipPrimary.SetARP()
	if err != nil {
		return err
	}

	// clear ipvs
	// this isn't in cleanup because cleanup shouldn't clobber a master if it comes online on the same node
	err = r.ipvs.Teardown(r.ctx)
	if err != nil {
		return err
	}

	// delete all k2i addresses from primary interface
	addresses, err := r.ipPrimary.Get()
	if err != nil {
		return err
	}
	for _, addr := range addresses {
		err := r.ipPrimary.Del(addr)
		if err != nil {
			return err
		}
	}

	// load this watcher instance into self
	ctxWatch, cxlWatch := context.WithCancel(r.ctx)
	r.ctxWatch = ctxWatch
	r.cxlWatch = cxlWatch

	// register the watcher for both nodes and the configmap
	r.watcher.ConfigMap(ctxWatch, "realserver", r.configChan)
	r.watcher.Nodes(ctxWatch, "director-nodes", r.nodeChan)
	return nil
}

func (r *realserver) setReconfiguring(v bool) {
	r.Lock()
	r.reconfiguring = v
	r.Unlock()
}

func (r *realserver) Start() error {
	r.logger.Info("Enter Start()")
	defer r.logger.Info("Exit Start()")
	if r.reconfiguring {
		return fmt.Errorf("unable to Start. reconfiguration already in progress.")
	}
	r.setReconfiguring(true)
	defer func() { r.setReconfiguring(false) }()

	err := r.setup()
	if err != nil {
		return err
	}

	go r.periodic()
	go r.watches()
	return nil
}

func (r *realserver) watches() {

	for {
		select {

		case nodes := <-r.nodeChan:
			r.logger.Debugf("recv on nodes, %d in list", len(nodes))
			var node types.Node
			found := false
			for _, n := range nodes {

				r.logger.Debugf("Name: %s, nodeName %s, equals %v", n.Name, r.nodeName, n.Name == r.nodeName)
				if n.Name == r.nodeName {
					node = n
					found = true
					break
				}
			}

			if !found {
				r.logger.Infof("node named %s not found, this shouldn't happen.", r.nodeName)
				continue
			}

			// filter list of nodes to just _my_ node.
			if types.NodeEqual(r.node, node) {
				r.logger.Debug("NODES ARE EQUAL")
				r.metrics.NodeUpdate("noop")
				continue
			}
			r.metrics.NodeUpdate("updated")
			r.Lock()
			r.node = node
			r.lastInboundUpdate = time.Now()
			r.Unlock()

		case config := <-r.configChan:
			// every time a new config kicks in, check parity and apply
			r.logger.Infof("recv on config: %+v", config)
			r.Lock()
			r.config = config
			r.lastInboundUpdate = time.Now()
			r.Unlock()
			r.metrics.ConfigUpdate()

		}
	}

}

// This function is the meat of the realserver struct. ALL CHANGES MADE HERE MUST BE MIRRORED IN pkg/bgp/worker.go
func (r *realserver) periodic() error {

	// every 60s, check parity and apply
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()

	checkTicker := time.NewTicker(100 * time.Millisecond)
	defer checkTicker.Stop()

	forcedReconfigureInterval := 10 * 60 * time.Second
	forceReconfigure := time.NewTicker(forcedReconfigureInterval)
	defer forceReconfigure.Stop()

	for {

		select {
		case <-forceReconfigure.C:
			if r.forcedReconfigure {
				start := time.Now()
				if err, _ := r.configure(true); err != nil {
					r.metrics.Reconfigure("error", time.Now().Sub(start))
					r.logger.Errorf("unable to apply ipv4 configuration, %v", err)
				}

				if err, _ := r.configure6(true); err != nil {
					r.metrics.Reconfigure("error", time.Now().Sub(start))
					r.logger.Errorf("unable to apply ipv4 configuration, %v", err)
				}

				// configure haproxy for v6-v4 NAT gateway
				err := r.ConfigureHAProxy()
				if err != nil {
					r.logger.Errorf("error applying haproxy config in realserver. %v", err)
					r.metrics.Reconfigure("error", time.Now().Sub(start))
					continue
				}
			}
		case <-t.C:
			// every 60 seconds, JFDI

			start := time.Now()
			r.logger.Infof("reconfig triggered due to periodic parity check")
			if err, _ := r.configure(false); err != nil {
				r.metrics.Reconfigure("error", time.Now().Sub(start))
				r.logger.Errorf("unable to apply ipv4 configuration, %v", err)
				continue
			}

			if err, _ := r.configure6(true); err != nil {
				r.metrics.Reconfigure("error", time.Now().Sub(start))
				r.logger.Errorf("unable to apply ipv4 configuration, %v", err)
			}

			// configure haproxy for v6-v4 NAT gateway
			err := r.ConfigureHAProxy()
			if err != nil {
				r.logger.Errorf("error applying haproxy config in realserver. %v", err)
				r.metrics.Reconfigure("error", time.Now().Sub(start))
				continue
			}

		case <-checkTicker.C:
			start := time.Now()
			// TODO: add metrics back in!
			// TODO: this has the same bug as the director! we MUST lock and deepcopy
			// all of the nodes + config to pass into r.configure() or else risk iterating
			// over a thing that's been replaced!

			// If there's nothing to do, there's nothing to do.
			r.logger.Debugf("reconfig math lastReconfigure=%v lastInboundUpdate=%v subtr=%v cond=%v",
				r.lastReconfigure,
				r.lastInboundUpdate,
				r.lastReconfigure.Sub(r.lastInboundUpdate),
				r.lastReconfigure.Sub(r.lastInboundUpdate) > 0)
			if r.lastReconfigure.Sub(r.lastInboundUpdate) > 0 {
				// No noop metric here - we only noop if a non-impactful config change makes it through
				r.logger.Debugf("no changes to configs since last reconfiguration completed")
				continue
			}

			r.metrics.QueueDepth(len(r.configChan))

			if r.config == nil || r.node.Name == "" {
				r.logger.Infof("configs %p, node name %s. skipping apply", r.config, r.node.Name)
				r.metrics.Reconfigure("noop", time.Now().Sub(start))
				continue
			}

			r.logger.Infof("reconfiguring TEST TEST TEST")
			err, _ := r.configure(false)
			if err != nil {
				r.logger.Errorf("error applying configuration in realserver. %v", err)
				r.metrics.Reconfigure("error", time.Now().Sub(start))
				continue
			}

			// configure haproxy for v6-v4 NAT gateway
			r.logger.Infof("WRITING HA PROXY")
			err = r.ConfigureHAProxy()
			if err != nil {
				r.logger.Errorf("error applying haproxy config in realserver. %v", err)
				r.metrics.Reconfigure("error", time.Now().Sub(start))
				continue
			}

			now := time.Now()
			r.logger.Infof("reconfiguration completed successfully in %v", now.Sub(start))
			r.lastReconfigure = start

			r.metrics.Reconfigure("complete", time.Now().Sub(start))

		case <-r.ctx.Done():
			return nil
		case <-r.ctxWatch.Done():
			r.doneChan <- struct{}{}
			return nil
		}

	}
}

// TODO: this needs to build a pair of service identifiers and port identifiers
// so, an array of ClusterIP:Port mirrored with an array of listen ports
// configureHAProxy determines whether the VIP should be configured at all, and
// generates a pair of slices of cluster-internal addresses and external listen ports.
func (r *realserver) ConfigureHAProxy() error {

	configSet := []haproxy.VIPConfig{}
	for ip, config := range r.config.Config6 {
		// make a haproxy server for each v6 VIP
		podIPs := map[string][]string{}
		servicePorts := map[string]string{}
		targetPorts := map[string]string{}
		for port, service := range config {
			// fetch the service config and pluck the clusterIP
			if !r.node.HasServiceRunning(service.Namespace, service.Service, service.PortName) {
				r.logger.Warnf("no service found for configuration [%s]:(%s/%s), skipping haproxy config", string(ip), service.Namespace, service.Service)
				continue
			}

			ips := r.node.GetPodIPs(service.Namespace, service.Service, service.PortName)
			podIPs[service.Service] = ips

			services := r.watcher.Services()
			serviceName := fmt.Sprintf("%s/%s", service.Namespace, service.Service)
			serviceForConfig := services[serviceName]
			if service == nil {
				return fmt.Errorf("error creating haproxy configs. Could not find kube service %s on ip [%s]", serviceName, string(ip))
			}

			// iterate over service ports and retrieve the one we want for this config
			// haproxy accepts uint16
			var targetPortForService string
			for _, servicePort := range serviceForConfig.Spec.Ports {
				fmt.Println("service name:", service.Service, serviceForConfig.Name)
				if service.Service == serviceForConfig.Name {
					fmt.Printf("match: %+v\n", servicePort.TargetPort)
					// this is an annoying kube type IntOrString, so we have to
					// decide which it is and then set it as uint16 here
					// additionally if targetport is not defined, targetPort == port:
					// kube docs: "Note: A Service can map any incoming port to a targetPort. By default and for convenience, the targetPort is set to the same value as the port field."
					// go from most specific to least here
					if servicePort.TargetPort.StrVal != "" {
						targetPortForService = servicePort.TargetPort.StrVal
					} else if servicePort.TargetPort.IntVal != 0 {
						targetPortForService = strconv.Itoa(int(servicePort.TargetPort.IntVal))
					} else {
						// targetPort == port
						targetPortForService = string(servicePort.Port)
					}
				}
			}

			targetPorts[service.Service] = targetPortForService
			servicePorts[service.Service] = port
		}

		for service, podIPs := range podIPs {
			haConfig := haproxy.VIPConfig{
				Addr6:       string(ip),
				PodIPs:      podIPs,
				TargetPort:  targetPorts[service],
				ServicePort: servicePorts[service],
			}
			// guard against initializing watcher race condition and haproxy
			// panics from 0-len lists
			fmt.Printf("VALID: %+v. Config: %+v\n", haConfig.IsValid(), haConfig)
			if haConfig.IsValid() {
				r.logger.Infof("adding haproxy config for ipv6: %+v", haConfig)
				configSet = append(configSet, haConfig)
			}
		}
	}

	r.logger.Debugf("got %d haproxy addresses to set", len(configSet))

	for _, cs := range configSet {
		if err := r.haproxy.Configure(cs); err != nil {
			return err
		}
	}

	return nil
}

func (r *realserver) configure(force bool) (error, int) {
	if force {
		r.logger.Info("forced reconfigure, not performing parity check")
	} else {
		same, err := r.checkConfigParity()
		if err != nil {
			r.logger.Errorf("parity check failed. %v", err)
			return err, 0
		} else if same {
			r.logger.Debugf("configuration has parity")
			return nil, 0
		}
	}

	removals := 0
	r.logger.Debugf("setting addresses")
	// add vip addresses to loopback
	if err := r.setAddresses(); err != nil {
		return err, removals
	}

	r.logger.Debugf("capturing iptables rules")
	// generate and apply iptables rules
	existing, err := r.iptables.Save()
	if err != nil {
		return err, removals
	}
	r.logger.Debugf("got %d existing rules", len(existing))

	r.logger.Debugf("generating iptables rules")
	// generate desired iptables configurations
	// generated, err := r.iptables.GenerateRules(r.config)
	// TODO: rename to the singular form
	generated, err := r.iptables.GenerateRulesForNodes(r.node, r.config, false)
	if err != nil {
		return err, removals
	}
	r.logger.Debugf("got %d generated rules", len(generated))

	r.logger.Debugf("merging iptables rules")
	merged, removals, err := r.iptables.Merge(generated, existing) // subset, all rules
	if err != nil {
		return err, removals
	}
	r.logger.Debugf("got %d merged rules", len(merged))

	r.logger.Debugf("applying updated rules")
	err = r.iptables.Restore(merged)
	if err != nil {
		// write erroneous rule set to file to capture later
		r.logger.Errorf("error applying rules. writing erroneous rule change to /tmp/realserver-ruleset-err for debugging")
		writeErr := ioutil.WriteFile("/tmp/realserver-ruleset-err", createErrorLog(err, iptables.BytesFromRules(merged)), 0644)
		if writeErr != nil {
			r.logger.Errorf("error writing to file; logging rules: %s", string(iptables.BytesFromRules(merged)))
		}

		return err, removals
	}
	return nil, removals
}

// for v6, we use HAProxy to get to pod network
// omit iptables rules here, set v6 addresses on loopback
func (r *realserver) configure6(force bool) (error, int) {
	if force {
		r.logger.Info("forced reconfigure, not performing parity check")
	} else {
		same, err := r.checkConfigParity()
		if err != nil {
			r.logger.Errorf("parity check failed. %v", err)
			return err, 0
		} else if same {
			r.logger.Debugf("configuration has parity")
			return nil, 0
		}
	}

	removals := 0
	r.logger.Debugf("setting addresses")
	// add vip addresses to loopback
	if err := r.setAddresses6(); err != nil {
		return err, removals
	}

	return nil, removals
}

func (r *realserver) checkConfigParity() (bool, error) {

	// =======================================================
	// == Perform check whether we're ready to start working
	// =======================================================
	if r.config == nil {
		return true, nil
	}

	// =======================================================
	// == Perform check on ethernet device configuration
	// =======================================================
	// pull existing eth configurations
	addresses, err := r.ipLoopback.Get()
	if err != nil {
		return false, err
	}

	// get desired set of VIP addresses
	vips := []string{}
	for ip, _ := range r.config.Config {
		vips = append(vips, string(ip))
	}
	sort.Sort(sort.StringSlice(vips))

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
		sort.Sort(sort.StringSlice(existingRules))
	}

	// generate desired iptables configurations
	generated, err := r.iptables.GenerateRules(r.config)
	if err != nil {
		return false, err
	}
	generatedRules := generated[r.iptables.BaseChain()].Rules
	sort.Sort(sort.StringSlice(generatedRules))

	// compare and return
	return (reflect.DeepEqual(vips, addresses) &&
		reflect.DeepEqual(existingRules, generatedRules)), nil

}

func (r *realserver) setAddresses() error {
	// pull existing
	configured, err := r.ipLoopback.Get()
	if err != nil {
		return err
	}

	// get desired set VIP addresses
	desired := []string{}
	for ip, _ := range r.config.Config {
		desired = append(desired, string(ip))
	}

	removals, additions := r.ipLoopback.Compare(configured, desired)

	for _, addr := range removals {
		r.logger.WithFields(logrus.Fields{"device": r.ipLoopback.Device(), "addr": addr, "action": "deleting"}).Info()
		err := r.ipLoopback.Del(addr)
		if err != nil {
			return err
		}
	}
	for _, addr := range additions {
		r.logger.WithFields(logrus.Fields{"device": r.ipLoopback.Device(), "addr": addr, "action": "adding"}).Info()
		err := r.ipLoopback.Add(addr)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *realserver) setAddresses6() error {
	// pull existing
	configured, err := r.ipLoopback.Get()
	if err != nil {
		return err
	}

	// get desired set VIP addresses
	desired := []string{}
	for ip, _ := range r.config.Config6 {
		fmt.Println("add config6 to loopback:", ip)
		desired = append(desired, string(ip))
	}

	removals, additions := r.ipLoopback.Compare(configured, desired)

	for _, addr := range removals {
		r.logger.WithFields(logrus.Fields{"device": r.ipLoopback.Device(), "addr": addr, "action": "deleting"}).Info()
		err := r.ipLoopback.Del(addr)
		if err != nil {
			return err
		}
	}
	for _, addr := range additions {
		r.logger.WithFields(logrus.Fields{"device": r.ipLoopback.Device(), "addr": addr, "action": "adding"}).Info()
		err := r.ipLoopback.Add(addr)
		if err != nil {
			return err
		}
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
