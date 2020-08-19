package system

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/comcast/ravel/pkg/types"

	"github.com/Sirupsen/logrus"
)

// The output of the watcher is a ConfigMap containing the desired configuration state
// for the load balancer backend server. To generate the configmap, a watcher will collect
// both ConfigMap data from the kubernetes cluster as well as Endpoint data and it will joing
// these data sources together to create a derivative ConfigMap containing only services that
// are running on this specific node.
//
// So, the way the watcher works is that it observes *both* the ConfigMap and the Endpoints
// sets for changes, and if any change is made to either, it generates a new ClusterConfig
// object internally. If the clusterconfig has changed from the prior configuration, we push
// it down the channel.
type Watcher interface {
	Services() map[string]*v1.Service

	Nodes(ctx context.Context, watcherID string, nodeChan chan types.NodesList)
	ConfigMap(ctx context.Context, watcherID string, cfgChan chan *types.ClusterConfig)
}

type target struct {
	ctx    context.Context
	config chan *types.ClusterConfig
	nodes  chan types.NodesList
}

type watcher struct {
	sync.Mutex

	configMapNamespace string
	configMapName      string
	configKey          string

	kube *kubernetes.Clientset

	allServices      map[string]*v1.Service
	allEndpoints     map[string]*v1.Endpoints
	endpointsForNode map[string]*v1.Endpoints
	configMap        *v1.ConfigMap

	// client watches.
	clientset  *kubernetes.Clientset
	nodeWatch  watch.Interface
	services   watch.Interface
	endpoints  watch.Interface
	configmaps watch.Interface

	// this is the 'official' configuration
	clusterConfig *types.ClusterConfig
	nodes         types.NodesList

	// these are the targets who will receive the configuration
	targets     map[string]target
	nodeTargets map[string]target

	// default listen services for vips in the vip pool
	autoSvc  string
	autoPort int

	// How long to wait to re-init watchers after a watcher error.
	// Starts at 1 second, then increments by 1 second every time
	// there's another error without an intervening successful event.
	watchBackoffDuration time.Duration

	publishChan chan *types.ClusterConfig

	ctx     context.Context
	logger  logrus.FieldLogger
	metrics watcherMetrics
}

func NewWatcher(ctx context.Context, kubeConfigFile, cmNamespace, cmName, configKey, lbKind string, autoSvc string, autoPort int, logger logrus.FieldLogger) (Watcher, error) {

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return nil, fmt.Errorf("error getting configuration from kubeconfig at %s. %v", kubeConfigFile, err)
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error initializing config. %v", err)
	}

	w := &watcher{
		ctx: ctx,

		clientset: clientset,

		configMapNamespace: cmNamespace,
		configMapName:      cmName,
		configKey:          configKey,

		allServices:      map[string]*v1.Service{},   // map of namespace/service to services
		allEndpoints:     map[string]*v1.Endpoints{}, // map of namespace/service:port to endpoints
		endpointsForNode: map[string]*v1.Endpoints{}, // map of namespace/service:port to endpoints on this node
		targets:          map[string]target{},
		nodeTargets:      map[string]target{},

		autoSvc:  autoSvc,
		autoPort: autoPort,

		publishChan: make(chan *types.ClusterConfig),

		logger:  logger.WithFields(logrus.Fields{"module": "watcher"}),
		metrics: NewWatcherMetrics(lbKind, configKey),
	}
	if err := w.initWatch(); err != nil {
		return nil, err
	}
	go w.watches()
	go w.watchPublish()

	return w, nil
}

func (w *watcher) stopWatch() {
	w.logger.Info("stopping all watches")
	w.nodeWatch.Stop()
	w.services.Stop()
	w.endpoints.Stop()
	w.configmaps.Stop()
}

func (w *watcher) initWatch() error {
	w.logger.Info("initializing all watches")
	start := time.Now()

	services, err := w.clientset.CoreV1().Services("").Watch(metav1.ListOptions{})
	w.metrics.WatchErr("services", err)
	if err != nil {
		return fmt.Errorf("error starting watch on services. %v", err)
	}

	endpoints, err := w.clientset.CoreV1().Endpoints("").Watch(metav1.ListOptions{})
	w.metrics.WatchErr("endpoints", err)
	if err != nil {
		services.Stop()
		return fmt.Errorf("error starting watch on endpoints. %v", err)
	}

	configmaps, err := w.clientset.CoreV1().ConfigMaps(w.configMapNamespace).Watch(metav1.ListOptions{})
	w.metrics.WatchErr("configmaps", err)
	if err != nil {
		services.Stop()
		endpoints.Stop()
		return fmt.Errorf("error starting watch on configmap. %v", err)
	}

	nodes, err := w.clientset.CoreV1().Nodes().Watch(metav1.ListOptions{})
	w.metrics.WatchErr("nodes", err)
	if err != nil {
		configmaps.Stop()
		services.Stop()
		endpoints.Stop()
		return fmt.Errorf("error starting watch on nodes. %v", err)
	}

	w.services = services
	w.endpoints = endpoints
	w.configmaps = configmaps
	w.nodeWatch = nodes
	w.metrics.WatchInit(time.Since(start))
	return nil
}

// Services documented in interface definition
func (w *watcher) Services() map[string]*v1.Service {
	w.Lock()
	defer w.Unlock()

	out := map[string]*v1.Service{}
	for k, v := range w.allServices {
		out[k] = v
	}
	return out
}

// resetWatch attempts to bootstrap initWatch indefinitely.
func (w *watcher) resetWatch() error {

	// increment backoff duration by 1 second, up to 30 seconds max
	// if errors occur without an intervening successful event arrival.
	// Most of the time, w.watchBackoffDuration will be zero, so this
	// expression sets it to 1 * time.Second. w.watchBackoffDuration gets
	// reset to 0 every time an event arrives successfully.
	w.watchBackoffDuration = (w.watchBackoffDuration + time.Second) % (30 * time.Second)

	w.stopWatch()

	// Sleep, because the channels that events arrive on are closed,
	// so no event arrive anyway. Linux kernel keeps on doing the IPVS
	// rules or iptables rules that are in place, this is not an interruption
	// in load balanced VIP:port service.
	time.Sleep(w.watchBackoffDuration)

	err := w.initWatch()
	if err != nil {
		return err
	}

	return nil
}

// runs forever (basically) and watches kubernetes for changes.
func (w *watcher) watches() {

	metricsUpdateTicker := time.NewTicker(60000 * time.Millisecond)
	totalUpdates, nodeUpdates, svcUpdates, epUpdates, cmUpdates := 0, 0, 0, 0, 0
	defer metricsUpdateTicker.Stop()
	for {
		select {
		case <-w.ctx.Done():
			w.logger.Debugf("context is done. calling w.Stop")
			w.stopWatch()
			return

		case evt, ok := <-w.services.ResultChan():
			if !ok || evt.Object == nil {
				err := w.resetWatch()
				if err != nil {
					w.logger.Infof("services evt arrived, resetWatch() failed: %v", err)
				}
				continue
			}
			w.watchBackoffDuration = 0
			svcUpdates++
			w.metrics.WatchData("services")
			w.logger.Debugf("got new service from result chan")
			svc := evt.Object.(*v1.Service)
			w.processService(evt.Type, svc.DeepCopy())

		case evt, ok := <-w.endpoints.ResultChan():
			if !ok || evt.Object == nil {
				err := w.resetWatch()
				if err != nil {
					w.logger.Infof("endpoints evt arrived, resetWatch() failed: %v", err)
				}
				continue
			}
			w.watchBackoffDuration = 0
			epUpdates++
			w.metrics.WatchData("endpoints")
			w.logger.Debugf("got new endpoints from result chan")
			ep := evt.Object.(*v1.Endpoints)
			w.processEndpoint(evt.Type, ep.DeepCopy())

		case evt, ok := <-w.configmaps.ResultChan():
			if !ok || evt.Object == nil {
				err := w.resetWatch()
				if err != nil {
					w.logger.Infof("configmaps evt arrived, resetWatch() failed: %v", err)
				}
				continue
			}
			w.watchBackoffDuration = 0
			cmUpdates++
			w.metrics.WatchData("configmaps")
			w.logger.Debugf("got new configmap from result chan")

			cm := evt.Object.(*v1.ConfigMap)
			fmt.Printf("======CM FROM WATCHER: [ %+v ]\n", cm)
			w.processConfigMap(evt.Type, cm.DeepCopy())

		case evt, ok := <-w.nodeWatch.ResultChan():
			if !ok || evt.Object == nil {
				err := w.resetWatch()
				if err != nil {
					w.logger.Infof("node watcher event, resetWatch() failed: %v", err)
				}
				continue
			}
			w.watchBackoffDuration = 0
			nodeUpdates++
			w.metrics.WatchData("nodes")
			w.logger.Debugf("got nodes update from result chan")
			n := evt.Object.(*v1.Node)
			w.processNode(evt.Type, n.DeepCopy())

		case <-metricsUpdateTicker.C:

			w.metrics.WatchBackoffDuration(w.watchBackoffDuration)

			w.logger.WithFields(logrus.Fields{
				"total":         totalUpdates,
				"nodes":         nodeUpdates,
				"services":      svcUpdates,
				"endpoints":     epUpdates,
				"configmap":     cmUpdates,
				"nodeTargets":   len(w.nodeTargets),
				"configTargets": len(w.targets),
			}).Infof("watch summary")
			totalUpdates, nodeUpdates, svcUpdates, epUpdates, cmUpdates = 0, 0, 0, 0, 0
		}
		// increment total only if the watchers didn't expire
		totalUpdates++

		if w.configMap == nil {
			w.logger.Warnf("configmap is nil. skipping publication")
			continue
		}

		// Build a new cluster config and publish it, maybe
		if modified, cc, err := w.buildClusterConfig(); err != nil {
			w.metrics.WatchClusterConfig("error")
			w.logger.Errorf("error building cluster config. %v", err)
		} else if modified {
			w.metrics.WatchClusterConfig("publish")
			w.logger.Debug("publishing new cluster config")
			w.publishChan <- cc
		} else {
			w.metrics.WatchClusterConfig("noop")
			w.logger.Debug("cluster config not modified")
		}

		// Here, do the nodes workflow and publish it definitely
		// Compute a new set of nodes and node endpoints. Compare that set of info to the
		// set of info that was last transmitted.  If it changed, publish it.
		if nodes, err := w.buildNodeConfig(); err != nil {
			w.logger.Infof("building node config: %v", err)
			// should it return here?
		} else {
			w.publishNodes(nodes)
		}
	}
}

// buildNodeConfig outputs an array of nodes containing a per-node, filtered
// array of endpoints for the node.  To get there it needs to eliminate irrelevant
// endpoints, generate an intermediate set of endpoints pertinent to each node,
// and assemble it all into an array.
func (w *watcher) buildNodeConfig() (types.NodesList, error) {

	if w.clusterConfig == nil || len(w.allEndpoints) == 0 {
		w.logger.Infof("w.clusterConfig %p, len allEndpoints %d", w.clusterConfig, len(w.allEndpoints))
		return types.NodesList{}, nil
	}

	nodes := w.nodes.Copy()

	// Index into w.nodes by node.Name.
	// Code later assumes node.Name == subset's *address.NodeName
	// so that we can match a v1.EndpointSubset to a types.Node
	nodeIndexes := make(map[string]int)
	for nodeIndex, node := range nodes {
		nodeIndexes[node.Name] = nodeIndex
	}

	// AddressTotals captures the total # of address records for any given
	// namespace/service:port triplet.  This, in combination with the pod totals
	// on a node, can determine the appropriate ratio of traffic that a node should
	// receive for a given service. These ratios are used by the ipvs master in order
	// to capture traffic for local services, outside of ipvs, when the master is not
	// running in an isolated context.
	addressTotals := map[string]int{}

	seenAlready := make(map[string]bool)
	for _, ep := range w.allEndpoints { // *v1.Endpoint
		keyprefix := ep.Namespace + "/" + ep.Name + "/"
		for _, subset := range ep.Subsets { // *v1.EndpointSubset

			for _, port := range subset.Ports {
				ident := types.MakeIdent(ep.Namespace, ep.Name, port.Name)
				addressTotals[ident] += len(subset.Addresses)
			}

			for _, address := range subset.Addresses { // *v1.Address
				if address.NodeName != nil && *address.NodeName != "" {
					addresskey := keyprefix + *address.NodeName + ":"
					naddress := []types.Address{
						types.Address{PodIP: address.IP, NodeName: *address.NodeName, Kind: address.TargetRef.Kind},
					}
					nsubset := types.Subset{Addresses: naddress}

					portkey := addresskey + ","
					for _, port := range subset.Ports {
						nsubset.Ports = append(nsubset.Ports, types.Port{Name: port.Name, Port: int(port.Port), Protocol: string(port.Protocol)})
						portkey += port.Name + ","
					}

					if _, ok := seenAlready[portkey]; ok {
						// This service has more than 1 pod on a node.
						// Add this subset to an existing endpoint for the node
						if idx, ok := nodeIndexes[*address.NodeName]; ok {
							for epIdx, endp := range nodes[idx].Endpoints {
								if endp.Namespace == ep.Namespace && endp.Service == ep.Name {
									// Should only be a single Subset of the endpoint
									nodes[idx].Endpoints[epIdx].Subsets[0].Addresses = append(nodes[idx].Endpoints[epIdx].Subsets[0].Addresses, naddress...)
								}
							}
						} // *address.NodeName doesn't match an index into nodes[] Is this a huge problem?
						continue
					}
					// Some work does get thrown away (nsubset) if more than 1 pod of a service
					// runs on a single node. Better than looking through subset.Ports twice

					seenAlready[portkey] = true

					var nep types.Endpoints
					nep.Namespace = ep.Namespace
					nep.Service = ep.Name
					nep.Subsets = append(nep.Subsets, nsubset)

					if idx, ok := nodeIndexes[*address.NodeName]; ok {
						nodes[idx].Endpoints = append(nodes[idx].Endpoints, nep)
					} // not sure how serious the "else" is here
				}
			}
		}
	}

	sort.Sort(nodes)
	for idx, _ := range nodes {
		nodes[idx].SortConstituents()
		nodes[idx].SetTotals(addressTotals)
	}

	return nodes, nil
}

func (w *watcher) watchPublish() {
	maxTimeout := 1000 * time.Millisecond
	baseTimeout := 250 * time.Millisecond
	timeout := baseTimeout

	// countdownActive denotes whether a countdown is currently running. If so, a
	// new timer will not be created when a new clusterconfig is received.
	countdownActive := false

	// countdown is used to trigger a reconfiguration
	countdown := time.NewTimer(timeout)
	countdown.Stop()

	var lastCC *types.ClusterConfig
	for {
		select {
		case cc := <-w.publishChan:
			w.logger.Debugf("watchPublish loop iteration - resv on publishChan - timeout=%v", timeout)
			lastCC = cc
			if countdownActive && timeout >= maxTimeout {
				continue
			}
			if countdownActive && !countdown.Stop() {
				<-countdown.C
			}
			countdown.Reset(timeout)
			countdownActive = true
			timeout = timeout * 2

		case <-countdown.C:
			w.logger.Debugf("watchPublish loop iteration - countdown timer expired - timeout=%v", timeout)
			countdownActive = false
			w.publish(lastCC)
			timeout = baseTimeout

		case <-w.ctx.Done():
			w.logger.Debugf("watchPublish loop iteration - parent context expired")
			countdown.Stop()
			return
		}
	}
}

func (w *watcher) publish(cc *types.ClusterConfig) {
	w.Lock()
	defer w.Unlock()

	w.clusterConfig = cc

	// generate a new full config record
	b, _ := json.Marshal(w.clusterConfig)
	sha := sha1.Sum(b)
	w.metrics.ClusterConfigInfo(base64.StdEncoding.EncodeToString(sha[:]), string(b))

	deletes := []string{}
	for key, tgt := range w.targets {

		// if the context associated with the output has been canceled, we
		// terminate here.
		select {
		case <-tgt.ctx.Done():
			w.logger.Infof("publish - removing watcher for key=%v", key)
			deletes = append(deletes, key)
			continue
		default:
		}

		// otherwise attempt to write to the output
		select {
		case tgt.config <- w.clusterConfig:
			w.logger.Debug("publish successfully published cluster config")
		case <-time.After(5 * time.Second):
			w.logger.Errorf("publish output channel full.")
			continue
		}
	}

	w.logger.Debugf("publish deleting %d cluster contexts ", len(deletes))
	for _, key := range deletes {
		delete(w.targets, key)
	}
}
func (w *watcher) publishNodes(nodes types.NodesList) {
	w.Lock()
	defer w.Unlock()

	nodeDeletes := []string{}
	for key, tgt := range w.nodeTargets {
		// if the context associated with the output has been canceled, we
		// terminate here.
		select {
		case <-tgt.ctx.Done():
			w.logger.Infof("publish - nodes - removing watcher for key=%v", key)
			nodeDeletes = append(nodeDeletes, key)
			continue
		default:
		}

		// otherwise attempt to write to the output
		select {
		case tgt.nodes <- nodes:
			w.logger.Debug("publish - nodes - successfully published nodes")
		case <-time.After(1 * time.Second):
			w.logger.Errorf("publish - nodes - output channel full.")
			continue
		}
	}

	w.logger.Debugf("publish deleting %d node contexts", len(nodeDeletes))
	for _, key := range nodeDeletes {
		delete(w.nodeTargets, key)
	}

}

// generates a new ClusterConfig object, compares it to the existing, and if different,
// mutates the state of watcher with the new value. it returns a boolean indicating whether
// the cluster state was changed, and an error
func (w *watcher) buildClusterConfig() (bool, *types.ClusterConfig, error) {
	rawConfig, err := w.extractConfigKey(w.configMap)
	if err != nil {
		return false, nil, err
	}

	// Update the config to eliminate any services that do not exist
	if err := w.filterConfig(rawConfig); err != nil {
		return false, nil, err
	}

	// Update the config to add the default listeners to all of the vips in the bip pool.
	if err := w.addListenersToConfig(rawConfig); err != nil {
		return false, nil, err
	}

	// compare. if they're the same we return false
	if reflect.DeepEqual(w.clusterConfig, rawConfig) {
		return false, nil, nil
	}

	return true, rawConfig, nil
}

func (w *watcher) processService(eventType watch.EventType, service *v1.Service) {
	w.Lock()
	defer w.Unlock()

	if eventType == "ERROR" {
		return
	}

	// first, set the value of w.service
	identity := service.ObjectMeta.Namespace + "/" + service.ObjectMeta.Name
	switch eventType {
	case "ADDED":
		w.logger.Debugf("processService - ADDED")
		w.allServices[identity] = service

	case "MODIFIED":
		w.logger.Debugf("processService - MODIFIED")
		w.allServices[identity] = service

	case "DELETED":
		w.logger.Debugf("processService - DELETED")
		delete(w.allServices, identity)

	default:
	}

}

func (w *watcher) processNode(eventType watch.EventType, node *v1.Node) {
	if eventType == "ERROR" {
		return
	}

	if w.nodes == nil {
		w.nodes = types.NodesList{}
	}

	// if a node is added, append to the array
	// if a node is modified, iterate and search the array for the node, then replace the record
	// if a node is deleted, iterate and search the array for the node, then remove the record
	if eventType == "ADDED" || eventType == "MODIFIED" {
		w.logger.Debugf("processNode - %s - %v", eventType, node)
		idx := -1
		for i, existing := range w.nodes {
			if existing.Name == node.Name {
				idx = i
				break
			}
		}
		n := types.NewNode(node)
		if idx != -1 {
			w.nodes[idx] = n
		} else {
			w.nodes = append(w.nodes, n)
		}
		sort.Sort(w.nodes)

	} else if eventType == "DELETED" {
		w.logger.Debugf("processNode - DELETED - %v", node)
		idx := -1
		for i, existing := range w.nodes {
			if existing.Name == node.Name {
				idx = i
				break
			}
		}
		if idx != -1 {
			w.nodes = append(w.nodes[:idx], w.nodes[idx+1:]...)
		}
	}

	w.logger.Debugf("have %d nodes", len(w.nodes))
}

func (w *watcher) processConfigMap(eventType watch.EventType, configmap *v1.ConfigMap) {
	if eventType == "ERROR" {
		return
	}

	// ensure that the configmap value is correct
	if configmap.Name != w.configMapName {
		return
	}

	w.configMap = configmap
}

func (w *watcher) processEndpoint(eventType watch.EventType, endpoints *v1.Endpoints) {
	if eventType == "ERROR" {
		return
	}

	// Endpoints now need to be added to a node, if the node is present.
	// This means there's a race between nodes and endpoints watchers when the program
	// first starts!
	// When an endpoint is added or modified, we need to do the following:
	// 1. Evaluate whether the endpoint is represented by the current cluster config
	// 2. Filter out endpoints that "don't matter" to us
	// 3. Build a list of endpoints for each node that we know about
	// 4. If necessary, update thenode to reflect changes to its endpoints
	// 5. Send a node update down the nodes channel (note that the nodes channel is only
	// 		updated now when a node update is inbound...)

	// first, set the value of w.endpoint
	identity := endpoints.ObjectMeta.Namespace + "/" + endpoints.ObjectMeta.Name
	switch eventType {
	case "ADDED":
		w.logger.Debugf("processEndpoint - ADDED")
		w.allEndpoints[identity] = endpoints

	case "MODIFIED":
		w.logger.Debugf("processEndpoint - MODIFIED")
		w.allEndpoints[identity] = endpoints

	case "DELETED":
		w.logger.Debugf("processEndpoint - DELETED")
		delete(w.allEndpoints, identity)

	default:
	}

	w.endpointsForNode = w.allEndpoints
	w.logger.Debugf("processEndpoint - endpoint counts: total=%d node=%d ", len(w.allEndpoints), len(w.endpointsForNode))
}

func (w *watcher) ConfigMap(ctx context.Context, name string, output chan *types.ClusterConfig) {
	w.logger.Debugf("registering configmap watcher for ctx=%v name=%s", ctx, name)
	w.Lock()
	defer w.Unlock()

	// adding the output to the map and sending it the current cluster config,
	// if any. This is necessary to ensure that a newly registered watcher on
	// the config gets whatever the latest configuration is. Without this step,
	// the workflow management portion won't be configured until a configuration
	// change is made by a user.
	w.targets[name] = target{
		ctx:    ctx,
		config: output,
	}
	if w.clusterConfig != nil {
		select {
		case output <- w.clusterConfig:
		default:
			w.logger.Warnf("unable to write cluster config to output channel for '%s'", name)
		}
	}
}

func (w *watcher) Nodes(ctx context.Context, name string, output chan types.NodesList) {
	w.logger.Debugf("registering node watcher for ctx=%v name=%s", ctx, name)
	w.Lock()
	defer w.Unlock()

	// adding the output to the map and sending it the current cluster config,
	// if any. This is necessary to ensure that a newly registered watcher on
	// the config gets whatever the latest configuration is. Without this step,
	// the workflow management portion won't be configured until a configuration
	// change is made by a user.
	w.nodeTargets[name] = target{
		ctx:   ctx,
		nodes: output,
	}
	if w.nodes != nil {
		select {
		case output <- w.nodes:
		default:
			w.logger.Warnf("unable to write nodes list to output channel for '%s'", name)
		}
	}
}

func (w *watcher) extractConfigKey(configmap *v1.ConfigMap) (*types.ClusterConfig, error) {
	// Unmarshal the config map, retrieving only the configuration matching the configKey
	clusterConfig, err := types.NewClusterConfig(configmap, w.configKey)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal configmap key '%s'. %v", w.configKey, err)
	} else if clusterConfig.Config == nil {
		return nil, fmt.Errorf("config is nil")
	}
	return clusterConfig, nil
}

// addListenersToConfig mutates the input types.ClusterConfig to add the autoSvc and autoPort
// from the watcher primary configuration, if that value is set.
func (w *watcher) addListenersToConfig(inCC *types.ClusterConfig) error {
	// bail out if there's nothing to do.
	if w.autoSvc == "" {
		return nil
	}

	// Iterate over the VIPPool and check whether Config contains a record for each of the vips.
	// If it does, check whether there's a record for w.autoPort. If so, skip. If not, create.
	// If not, create.
	autoSvc, err := types.NewServiceDef(w.autoSvc)
	if err != nil {
		return fmt.Errorf("unable to add listener to config. %v", err)
	}
	autoSvc.IPVSOptions.RawForwardingMethod = "i"
	for _, vip := range inCC.VIPPool {
		sVip := types.ServiceIP(vip)
		sPort := strconv.Itoa(w.autoPort)
		if _, ok := inCC.Config[sVip]; !ok {
			// Create a new portmap
			inCC.Config[sVip] = types.PortMap{
				sPort: autoSvc,
			}
		} else if _, ok := inCC.Config[sVip][sPort]; !ok {
			// create a new record in the portmap
			inCC.Config[sVip][sPort] = autoSvc
		} else {
			// do nothing
		}
	}

	w.logger.Debugf("generated cluster config: %+v", inCC)
	return nil
}

// serviceHasValidEndpoints filters out any service that does not have
// an endpoint in its endpoints list. Kubernetes will remove these services
// from the kube-proxy, and we should, too.
func (w *watcher) serviceHasValidEndpoints(ns, svc string) bool {
	service := fmt.Sprintf("%s/%s", ns, svc)

	if ep, ok := w.allEndpoints[service]; !ok {
		return false
	} else {
		for _, subset := range ep.Subsets {
			if len(subset.Addresses) != 0 {
				return true
			}
		}
	}
	return false
}

func (w *watcher) userServiceInEndpoints(ns, svc, portName string) bool {
	service := fmt.Sprintf("%s/%s", ns, svc)
	if ep, ok := w.allEndpoints[service]; !ok {
		return false
	} else {
		for _, subset := range ep.Subsets {
			for _, port := range subset.Ports {
				if port.Name == portName {
					return true
				}
			}
		}
	}
	return false
}

// serviceClusterIPisNone returns a boolean value indicating whether the
// clusterIP value is set in the target service. If not, we do not configure
// the service.
func (w *watcher) serviceClusterIPisSet(ns, svc string) bool {

	service := fmt.Sprintf("%s/%s", ns, svc)

	if s, ok := w.allServices[service]; !ok {
		return false
	} else {
		if s.Spec.ClusterIP == "None" || s.Spec.ClusterIP == "" {
			return false
		}
	}
	return true
}

// filtering out any service from the clusterconfig that is not present in the retrieved services.
// This ensures that we do not attempt to create a load balancer that points to a service that does not yet exist.
// Note that even though iptables has a secondary filter to remove service references that are not present in
// the kube-services chain, this is necessary in order to ensure that the load balancer does not hold a lock
// on a chain that should be deleted, which would result in kube-proxy's update failing.
func (w *watcher) filterConfig(inCC *types.ClusterConfig) error {

	newConfig := map[types.ServiceIP]types.PortMap{}

	// walk the input configmap and check for matches.
	// if no match is found, continue. if a match is found, add the entire portMap back into the config
	for lbVIP, portMap := range inCC.Config {
		found := false
		newPortMap := types.PortMap{}
		for port, lbTarget := range portMap {
			// check for a match!
			match := fmt.Sprintf("%s/%s:%s", lbTarget.Namespace, lbTarget.Service, lbTarget.PortName)
			if !w.userServiceInEndpoints(lbTarget.Namespace, lbTarget.Service, lbTarget.PortName) {
				// if the service doesn't exist in kube's records, we don't create it
				w.logger.Debugf("filtering missing service - %s", match)
				continue
			} else if !w.serviceClusterIPisSet(lbTarget.Namespace, lbTarget.Service) {
				w.logger.Debugf("filtering service with no ClusterIP - %s", match)
				continue
			} else if !w.serviceHasValidEndpoints(lbTarget.Namespace, lbTarget.Service) {
				w.logger.Debugf("filtering service with no Endpoints - %s", match)
				continue
			}
			found = true
			newPortMap[port] = lbTarget
		}
		if found {
			newConfig[lbVIP] = newPortMap
		}
	}

	inCC.Config = newConfig
	return nil
}
