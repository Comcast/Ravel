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
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	watchtools "k8s.io/client-go/tools/watch"

	"github.com/Comcast/Ravel/pkg/types"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// Watcher defines an interface for a ConfigMap containing the desired configuration state
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

// NewWatcher creates a new Watcher struct, which is used to watch services, endpoints, and more
func NewWatcher(ctx context.Context, kubeConfigFile, cmNamespace, cmName, configKey, lbKind string, autoSvc string, autoPort int, logger logrus.FieldLogger) (Watcher, error) {

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return nil, fmt.Errorf("error getting configuration from kubeconfig at %s. %v", kubeConfigFile, err)
	}
	log.Debugln("Created kube client for watcher")

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
		log.Errorln("Failed to init watcher with error:", err)
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
	w.logger.Info("watcher: initializing all watches")
	start := time.Now()

	// TODO - optimize by limiting fields that are watched
	serviceListWatcher := cache.NewListWatchFromClient(w.clientset.CoreV1().RESTClient(), "services", v1.NamespaceAll, fields.Everything())
	_, _, servicesChan, _ := watchtools.NewIndexerInformerWatcher(serviceListWatcher, &v1.Service{})
	w.services = servicesChan

	// services, err := w.clientset.CoreV1().Services("").Watch(w.ctx, metav1.ListOptions{})
	// w.metrics.WatchErr("services", err)
	// if err != nil {
	// 	return fmt.Errorf("watcher: error starting watch on services. %v", err)
	// }

	endpointListWatcher := cache.NewListWatchFromClient(w.clientset.CoreV1().RESTClient(), "endpoints", v1.NamespaceAll, fields.Everything())
	_, _, endpointChan, _ := watchtools.NewIndexerInformerWatcher(endpointListWatcher, &v1.Endpoints{})
	w.endpoints = endpointChan

	// endpoints, err := w.clientset.CoreV1().Endpoints("").Watch(w.ctx, metav1.ListOptions{})
	// w.metrics.WatchErr("endpoints", err)
	// if err != nil {
	// 	services.Stop()
	// 	return fmt.Errorf("watcher: error starting watch on endpoints. %v", err)
	// }

	configmapListWatcher := cache.NewListWatchFromClient(w.clientset.CoreV1().RESTClient(), "configmaps", v1.NamespaceAll, fields.Everything())
	_, _, configmapChan, _ := watchtools.NewIndexerInformerWatcher(configmapListWatcher, &v1.ConfigMap{})
	w.configmaps = configmapChan

	// configmaps, err := w.clientset.CoreV1().ConfigMaps(w.configMapNamespace).Watch(w.ctx, metav1.ListOptions{})
	// w.metrics.WatchErr("configmaps", err)
	// if err != nil {
	// 	services.Stop()
	// 	endpoints.Stop()
	// 	return fmt.Errorf("error starting watch on configmap. %v", err)
	// }

	nodesListWatcher := cache.NewListWatchFromClient(w.clientset.CoreV1().RESTClient(), "nodes", v1.NamespaceAll, fields.Everything())
	_, _, nodeChan, _ := watchtools.NewIndexerInformerWatcher(nodesListWatcher, &v1.Node{})
	w.nodeWatch = nodeChan

	// nodes, err := w.clientset.CoreV1().Nodes().Watch(w.ctx, metav1.ListOptions{})
	// w.metrics.WatchErr("nodes", err)
	// if err != nil {
	// 	configmaps.Stop()
	// 	services.Stop()
	// 	endpoints.Stop()
	// 	return fmt.Errorf("watcher: error starting watch on nodes. %v", err)
	// }

	// w.services = services
	// w.endpoints = endpoints
	// w.configmaps = configmaps
	// w.nodeWatch = nodes
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

	metricsUpdateTicker := time.NewTicker(time.Minute)
	totalUpdates, nodeUpdates, svcUpdates, epUpdates, cmUpdates := 0, 0, 0, 0, 0
	defer metricsUpdateTicker.Stop()

	for {

		select {
		case <-w.ctx.Done():
			log.Debugln("watcher: context is done. calling w.stopWatch")
			w.stopWatch()
			return

		case evt, ok := <-w.services.ResultChan():
			log.Debugln("watcher: services chan got an event:", evt)
			if !ok || evt.Object == nil {
				if !ok {
					log.Debugln("watcher: servicesChan closed - restarting watch")
				}
				if evt.Object == nil {
					log.Debugln("watcher: servicesChan event object was nil - restarting watch")
				}
				err := w.resetWatch()
				if err != nil {
					w.logger.Errorf("watcher: resetWatch() failed: %v", err)
				}
				continue
			}
			w.watchBackoffDuration = 0
			svcUpdates++
			w.metrics.WatchData("services")
			// w.logger.Debugf("got new service from result chan")
			svc := evt.Object.(*v1.Service)
			w.processService(evt.Type, svc.DeepCopy())

		case evt, ok := <-w.endpoints.ResultChan():
			log.Debugln("watcher: endpoints chan got an event:", evt)
			if !ok || evt.Object == nil {
				if !ok {
					log.Debugln("watcher: endpointsChan closed - restarting watch")
				}
				if evt.Object == nil {
					log.Debugln("watcher: endpointsChan event object was nil - restarting watch")
				}
				err := w.resetWatch()
				if err != nil {
					w.logger.Errorf("watcher: resetWatch() failed: %v", err)
				}
				continue
			}
			w.watchBackoffDuration = 0
			epUpdates++
			w.metrics.WatchData("endpoints")
			// w.logger.Debugf("got new endpoints from result chan")
			ep := evt.Object.(*v1.Endpoints)
			w.processEndpoint(evt.Type, ep.DeepCopy())

		case evt, ok := <-w.configmaps.ResultChan():
			log.Debugln("watcher: configmaps chan got an event:", evt)
			if !ok || evt.Object == nil {
				if !ok {
					log.Debugln("watcher: configmapsChan closed - restarting watch")
				}
				if evt.Object == nil {
					log.Debugln("watcher: configmapsChan event object was nil - restarting watch")
				}
				err := w.resetWatch()
				if err != nil {
					w.logger.Errorf("watcher: resetWatch() failed: %v", err)
				}
				continue
			}
			w.watchBackoffDuration = 0
			cmUpdates++
			w.metrics.WatchData("configmaps")
			// w.logger.Debugf("got new configmap from result chan")

			cm := evt.Object.(*v1.ConfigMap)
			w.processConfigMap(evt.Type, cm.DeepCopy())

		case evt, ok := <-w.nodeWatch.ResultChan():
			log.Debugln("watcher: nodeWatch chan got an event:", evt)
			if !ok || evt.Object == nil {
				if !ok {
					log.Debugln("watcher: nodeChan closed - restarting watch")
				}
				if evt.Object == nil {
					log.Debugln("watcher: nodeChan event object was nil - restarting watch")
				}
				err := w.resetWatch()
				if err != nil {
					w.logger.Errorf("watcher: resetWatch() failed: %v", err)
				}
				continue
			}
			w.watchBackoffDuration = 0
			nodeUpdates++
			w.metrics.WatchData("nodes")
			// w.logger.Debugf("got nodes update from result chan")
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
		log.Debugln("watcher: update count is now:", totalUpdates)

		if w.configMap == nil {
			w.logger.Warnf("configmap is nil. skipping publication")
			continue
		}

		// Build a new cluster config and publish it, maybe
		modified, cc, err := w.buildClusterConfig()
		if err != nil {
			w.metrics.WatchClusterConfig("error")
			w.logger.Errorf("watcher: error building cluster config. %v", err)
		}

		if modified {
			w.metrics.WatchClusterConfig("publish")
			w.logger.Debug("watcher: publishing new cluster config")
			w.publishChan <- cc
		} else {
			w.metrics.WatchClusterConfig("noop")
			// w.logger.Debug("watcher: cluster config not modified")
		}

		// Here, do the nodes workflow and publish it definitely
		// Compute a new set of nodes and node endpoints. Compare that set of info to the
		// set of info that was last transmitted.  If it changed, publish it.
		nodes, err := w.buildNodeConfig()
		if err != nil {
			w.logger.Errorf("watcher: error building node config: %v", err)
			continue
		}
		w.logger.Infof("watcher: publishing node config")
		w.publishNodes(nodes)
	}
}

// buildNodeConfig outputs an array of nodes containing a per-node, filtered
// array of endpoints for the node.  To get there it needs to eliminate irrelevant
// endpoints, generate an intermediate set of endpoints pertinent to each node,
// and assemble it all into an array.
func (w *watcher) buildNodeConfig() (types.NodesList, error) {

	if w.clusterConfig == nil || len(w.allEndpoints) == 0 {
		// w.logger.Infof("w.clusterConfig %p, len allEndpoints %d", w.clusterConfig, len(w.allEndpoints))
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
						{PodIP: address.IP, NodeName: *address.NodeName, Kind: address.TargetRef.Kind},
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
	for idx := range nodes {
		nodes[idx].SortConstituents()
		nodes[idx].SetTotals(addressTotals)
	}

	return nodes, nil
}

func (w *watcher) watchPublish() {
	log.Debugln("watcher: Starting to watch for publishes")

	// publishDelay is how long we wait to batch up more changes before publishing
	publishDelay := 500 * time.Millisecond

	// maxTimeout is the maximum time we will wait between publishes, even if
	// changes keep coming
	maxTimeout := 2 * time.Second

	// configToPublish holds the cluster configuration that will be published
	var configToPublish *types.ClusterConfig

	for {
		select {
		// this occurs when a publish is called for
		case c := <-w.publishChan:
			log.Debugln("watcher: publishChan got a config to publish")

			// set this incoming config as the config we plan to publish
			// after we wait the prerequensite batching time
			configToPublish = c

			// start a maxTimeoutTimer that fires after the maximum time to publish
			// this batch has passed
			maxTimeoutTimer := time.NewTimer(maxTimeout)
			// start a maxTimeout timer indicate when we can publish if no furhter
			// updates have been recieved
			publishDelayTimer := time.NewTimer(publishDelay)

			// we watch to see if the maxTimeoutTimer strikes, or the
			// publishDelay timer strikes, then we publish.  If more publishes come
			// in, we refresh the publish delay timer
			var publishComplete bool
			for {
				// end this loop once the publish fires
				if publishComplete {
					break
				}

				select {
				case c := <-w.publishChan:
					log.Debugln("watcher: publishChan got a config to publish but batched it")
					configToPublish = c
					// for every additional new publish config that comes in,
					// we reset the publish delay timer
					publishDelayTimer.Reset(publishDelay)
				case <-maxTimeoutTimer.C:
					log.Debugln("watcher: publishChan published due to max timeout")
					w.publish(configToPublish)
					publishComplete = true
				case <-publishDelayTimer.C:
					log.Debugln("watcher: publishChan published due to max delay timeout")
					w.publish(configToPublish)
					publishComplete = true
				case <-w.ctx.Done():
					log.Debugln("watcher: publishChan shutting down while waiting for publish batch")
					return
				}
			}
		case <-w.ctx.Done():
			log.Debugln("watcher: publishChan shutting down")
			return
		}
	}
}

// 	select {
// 	case cc := <-w.publishChan:
// 		lastcc = cc
// 		// w.logger.Debugf("watchPublish loop iteration - resv on publishChan - timeout=%v", timeout)
// 		log.Debugln("watcher: publish signal recieved. Waiting for 2 second timeout")
// 		countdown.Reset(timeout)

// 	case <-countdown.C:
// 		// w.logger.Debugf("watchPublish loop iteration - countdown timer expired - timeout=%v", timeout)
// 		log.Debugln("watcher: publishing cluster config:", *lastCC)
// 		countdownActive = false
// 		w.publish(lastCC)
// 		timeout = baseTimeout

// 	case <-w.ctx.Done():
// 		// w.logger.Debugf("watchPublish loop iteration - parent context expired")
// 		countdown.Stop()
// 		return
// 	}
// }

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
			// w.logger.Infof("publish - removing watcher for key=%v", key)
			deletes = append(deletes, key)
			continue
		default:
		}

		// otherwise attempt to write to the output
		select {
		case tgt.config <- w.clusterConfig:
			// w.logger.Debug("publish successfully published cluster config")
		case <-time.After(5 * time.Second):
			w.logger.Errorf("publish output channel full.")
			continue
		}
	}

	// w.logger.Debugf("publish deleting %d cluster contexts ", len(deletes))
	for _, key := range deletes {
		delete(w.targets, key)
	}
}
func (w *watcher) publishNodes(nodes types.NodesList) {
	startTime := time.Now()
	log.Debugln("watcher: publishNodes running")
	defer log.Debugln("watcher: publishNodes completed in", time.Since(startTime))
	w.Lock()
	defer w.Unlock()

	nodeDeletes := []string{}
	for key, tgt := range w.nodeTargets {
		// if the context associated with the output has been canceled, we
		// terminate here.
		select {
		case <-tgt.ctx.Done():
			// w.logger.Infof("publish - nodes - removing watcher for key=%v", key)
			nodeDeletes = append(nodeDeletes, key)
			continue
		default:
		}

		// otherwise attempt to write to the output
		select {
		case tgt.nodes <- nodes:
			w.logger.Debug("watcher: publishNodes - successfully published nodes")
		case <-time.After(1 * time.Second):
			w.logger.Errorf("watcher: publishNodes - output channel full.")
			continue
		}
	}

	// w.logger.Debugf("publish deleting %d node contexts", len(nodeDeletes))
	for _, key := range nodeDeletes {
		log.Println("watcher: removed node target:", key)
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

	// determine if the config has changed. if it has not, then we just return
	if !w.hasConfigChanged(w.clusterConfig, rawConfig) {
		return false, nil, nil
	}
	log.Println("watcher: cluster config was changed")

	existingJSON, err := json.Marshal(w.clusterConfig)
	if err != nil {
		log.Errorln("failed to marshal existing json for debug display:", err)
	}
	newJSON, err := json.Marshal(w.clusterConfig)
	if err != nil {
		log.Errorln("failed to marshal new json for debug display:", err)
	}
	println("watcher: existing config JSON:", string(existingJSON))
	println("watcher: new config JSON:", string(newJSON))

	return true, rawConfig, nil
}

// hasConfigChanged determines if the cluster configuration has actually changed
func (w *watcher) hasConfigChanged(currentConfig *types.ClusterConfig, newConfig *types.ClusterConfig) bool {

	// if both configs are nil, we consider them as unchanged
	if currentConfig == nil && newConfig == nil {
		log.Warningln("watcher: currentConfig and newConfig were both nil")
		return false
	}

	// if either configs have a nil (but not both), we decide things have changed
	if currentConfig == nil {
		log.Warningln("watcher: currentConfig was nil")
		return true
	}
	if newConfig == nil {
		log.Warningln("watcher: newConfig was nil")
		return true
	}

	// first, check if reflect.DeepEqual determines they are the same. If
	// DeepEqual says they haven't changed, then they havent.  If DeepEqual
	// says they have changed, then it might just be detecting a difference
	// in the order of values, so we need to look further.  As of v2.5.6,
	// this was _always_ returning that the config changed, even if you
	// can confirm they haven't with a manual diff of the JSON version of
	// both configs.
	if reflect.DeepEqual(currentConfig, newConfig) {
		log.Infoln("watcher: deep equal matches - no values changed")
		return false
	}

	// if the Config property is a nil map, then we indicate nothing has changed
	// in an assumption that something is wrong or not yet populated
	if currentConfig.Config == nil || newConfig.Config == nil {
		log.Warningln("watcher: Config property was empty on new or current config")
		return false
	}

	// check all values in the Config map
	// if the length of values are different, then they are not equal
	if len(currentConfig.Config) != len(newConfig.Config) {
		log.Infoln("watcher: Config value count has changed")
		return true
	}

	for currentKey, currentValue := range currentConfig.Config {
		for currentPortMapKey, currentPortMapValue := range currentValue {
			if newConfig.Config[currentKey][currentPortMapKey].IPV4Enabled != currentPortMapValue.IPV4Enabled {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "IPv4 Enabled has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].IPV6Enabled != currentPortMapValue.IPV6Enabled {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "IPv6 Enabled has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].ProxyProtocolEnabled != currentPortMapValue.ProxyProtocolEnabled {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "ProxyProtocolEnabled has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].TCPEnabled != currentPortMapValue.TCPEnabled {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "TCPEnabled has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].UDPEnabled != currentPortMapValue.UDPEnabled {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "UDPEnabled has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].IPVSOptions.Flags != currentPortMapValue.IPVSOptions.Flags {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "IPVS Flags have changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].IPVSOptions.RawForwardingMethod != currentPortMapValue.IPVSOptions.RawForwardingMethod {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "RawForwardingMethod has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].IPVSOptions.RawScheduler != currentPortMapValue.IPVSOptions.RawScheduler {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "RawScheduler has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].IPVSOptions.RawLThreshold != currentPortMapValue.IPVSOptions.RawLThreshold {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "RawLThreshold has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].IPVSOptions.RawUThreshold != currentPortMapValue.IPVSOptions.RawUThreshold {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "RawUThreshold has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].Namespace != currentPortMapValue.Namespace {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "Namespace has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].PortName != currentPortMapValue.PortName {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "PortName has changed")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey].Service != currentPortMapValue.Service {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "Service Name has changed")
				return true
			}
		}
	}

	// if the Config property is a nil map, then we indicate nothing has changed
	// in an assumption that something is wrong or not yet populated
	if currentConfig.Config6 == nil || newConfig.Config6 == nil {
		log.Warningln("watcher: Config6 was empty on new or current config")
		return false
	}

	// check all values in the Config6 map
	// if the length of values are different, then they are not equal
	if len(currentConfig.Config6) != len(newConfig.Config6) {
		log.Infoln("watcher: Config6 value count has changed")
		return true
	}
	for currentKey, currentValue := range currentConfig.Config6 {
		for currentPortMapKey, currentPortMapValue := range currentValue {
			if newConfig.Config6[currentKey][currentPortMapKey].IPV4Enabled != currentPortMapValue.IPV4Enabled {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 IPv4 Enabled has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].IPV6Enabled != currentPortMapValue.IPV6Enabled {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 IPv6 Enabled has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].ProxyProtocolEnabled != currentPortMapValue.ProxyProtocolEnabled {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 ProxyProtocolEnabled has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].TCPEnabled != currentPortMapValue.TCPEnabled {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 TCPEnabled has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].UDPEnabled != currentPortMapValue.UDPEnabled {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 UDPEnabled has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].IPVSOptions.Flags != currentPortMapValue.IPVSOptions.Flags {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 IPVS Flags have changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].IPVSOptions.RawForwardingMethod != currentPortMapValue.IPVSOptions.RawForwardingMethod {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 RawForwardingMethod has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].IPVSOptions.RawScheduler != currentPortMapValue.IPVSOptions.RawScheduler {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 RawScheduler has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].IPVSOptions.RawLThreshold != currentPortMapValue.IPVSOptions.RawLThreshold {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 RawLThreshold has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].IPVSOptions.RawUThreshold != currentPortMapValue.IPVSOptions.RawUThreshold {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 RawUThreshold has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].Namespace != currentPortMapValue.Namespace {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 Namespace has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].PortName != currentPortMapValue.PortName {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 PortName has changed")
				return true
			}
			if newConfig.Config6[currentKey][currentPortMapKey].Service != currentPortMapValue.Service {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 Service Name has changed")
				return true
			}
		}
	}

	if currentConfig.IPV6 == nil || newConfig.IPV6 == nil {
		log.Warningln("watcher: IPV6 was empty on new or current config")
		return false
	}
	// Check the IPV6 map for changes
	if len(currentConfig.IPV6) != len(newConfig.IPV6) {
		log.Infoln("watcher: IPV6 configuration count has changed")
		return true
	}
	for currentKey, currentValue := range currentConfig.IPV6 {
		if newConfig.IPV6[currentKey] != currentValue {
			log.Infoln("watcher: IPV6 configuration has changed")
			return true
		}
	}

	if currentConfig.MTUConfig == nil || newConfig.MTUConfig == nil {
		log.Warningln("watcher: MTUConfig was empty on new or current config")
		return false
	}
	// Check the MTUConfig map
	if len(currentConfig.MTUConfig) != len(newConfig.MTUConfig) {
		log.Infoln("watcher: MTU configuration has changed count")
		return true
	}
	for currentKey, currentValue := range currentConfig.MTUConfig {
		if newConfig.MTUConfig[currentKey] != currentValue {
			log.Infoln("watcher: MTU configuration has changed")
			return true
		}
	}

	// Check the MTUConfig6 map
	if currentConfig.MTUConfig6 == nil || newConfig.MTUConfig6 == nil {
		log.Warningln("watcher: MTUConfig6 was empty on new or current config")
		return false
	}
	if len(currentConfig.MTUConfig6) != len(newConfig.MTUConfig6) {
		log.Infoln("watcher: MTU v6 configuration has changed count")
		return true
	}
	for currentKey, currentValue := range currentConfig.MTUConfig6 {
		if newConfig.MTUConfig6[currentKey] != currentValue {
			log.Infoln("watcher: MTU v6 configuration has changed")
			return true
		}
	}

	// Check the NodeLabels map
	if currentConfig.NodeLabels == nil || newConfig.NodeLabels == nil {
		log.Warningln("watcher: NodeLabels was empty on new or current config")
		return false
	}
	if len(currentConfig.NodeLabels) != len(newConfig.NodeLabels) {
		log.Infoln("watcher: Node labels have changed count")
		return true
	}
	for currentKey, currentValue := range currentConfig.NodeLabels {
		if newConfig.NodeLabels[currentKey] != currentValue {
			log.Infoln("watcher: Node labels have changed for", currentKey)
			return true
		}
	}

	// Check the VIPPool []string
	if currentConfig.VIPPool == nil || newConfig.VIPPool == nil {
		log.Warningln("watcher: VIPPool was empty on new or current config")
		return false
	}
	if len(currentConfig.VIPPool) != len(newConfig.VIPPool) {
		return true
	}
	for _, currentValue := range currentConfig.VIPPool {
		foundValue := false
		for _, v := range newConfig.VIPPool {
			if v == currentValue {
				foundValue = true
				break
			}
		}
		if !foundValue {
			log.Infoln("watcher: Config VIP Pool has changed")
			return true
		}
	}

	return false
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
		log.Debugln("watcher: service added:", service.Name)
		// w.logger.Debugf("processService - ADDED")
		w.allServices[identity] = service

	case "MODIFIED":
		log.Debugln("watcher: service modified:", service.Name)
		// w.logger.Debugf("processService - MODIFIED")
		w.allServices[identity] = service

	case "DELETED":
		log.Debugln("watcher: service deleted:", service.Name)
		// w.logger.Debugf("processService - DELETED")
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
		log.Debugln("watcher: node added or modified:", node.Name)
		// w.logger.Debugf("processNode - %s - %v", eventType, node)
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
		log.Debugln("watcher: node deleted:", node.Name)
		// w.logger.Debugf("processNode - DELETED - %v", node)
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

	// w.logger.Debugf("have %d nodes", len(w.nodes))
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
		log.Debugln("watcher: endpoint added:", endpoints.Name)
		// w.logger.Debugf("processEndpoint - ADDED")
		w.allEndpoints[identity] = endpoints

	case "MODIFIED":
		log.Debugln("watcher: endpoint modified:", endpoints.Name)
		// w.logger.Debugf("processEndpoint - MODIFIED")
		w.allEndpoints[identity] = endpoints

	case "DELETED":
		log.Debugln("watcher: endpoint deleted:", endpoints.Name)
		// w.logger.Debugf("processEndpoint - DELETED")
		delete(w.allEndpoints, identity)

	default:
	}

	w.endpointsForNode = w.allEndpoints
	// w.logger.Debugf("processEndpoint - endpoint counts: total=%d node=%d ", len(w.allEndpoints), len(w.endpointsForNode))
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

	log.Debugln("unicorns: addListenersToConfig")

	// bail out if there's nothing to do.
	if w.autoSvc == "" {
		log.Debugln("unicorns: not adding unicorns listner because the autoSvc is blank")
		return nil
	}

	// Iterate over the VIPPool and check whether Config contains a record for each of the vips.
	// If it does, check whether there's a record for w.autoPort. If so, skip. If not, create.
	// If not, create.
	autoSvc, err := types.NewServiceDef(w.autoSvc)
	if err != nil {
		return fmt.Errorf("unicorns: unable to add listener to config. %v", err)
	}
	autoSvc.IPVSOptions.RawForwardingMethod = "i"
	for _, vip := range inCC.VIPPool {
		sVip := types.ServiceIP(vip)
		sPort := strconv.Itoa(w.autoPort)
		if _, ok := inCC.Config[sVip]; !ok {
			// Create a new portmap
			// log.Debugln("unicorns: adding unicorns service IP:", sVip, autoSvc)
			inCC.Config[sVip] = types.PortMap{
				sPort: autoSvc,
			}
		} else if _, ok := inCC.Config[sVip][sPort]; !ok {
			// log.Debugln("unicorns: adding unicorns port:", sVip, sPort, autoSvc)
			// create a new record in the portmap
			inCC.Config[sVip][sPort] = autoSvc
		} else {
			// do nothing
			// log.Debugln("unicorns: not adding unicorns for:", sVip, sPort)
		}
	}

	// log.Debugln("unicorns: done configuring unicorns listeners")
	// w.logger.Debugf("generated cluster config: %+v", inCC)
	return nil
}

// serviceHasValidEndpoints filters out any service that does not have
// an endpoint in its endpoints list. Kubernetes will remove these services
// from the kube-proxy, and we should, too.
func (w *watcher) serviceHasValidEndpoints(ns, svc string) bool {
	service := fmt.Sprintf("%s/%s", ns, svc)

	if ep, ok := w.allEndpoints[service]; ok {
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
	if ep, ok := w.allEndpoints[service]; ok {
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

	if s, ok := w.allServices[service]; ok {
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
			// match := fmt.Sprintf("%s/%s:%s", lbTarget.Namespace, lbTarget.Service, lbTarget.PortName)
			if !w.userServiceInEndpoints(lbTarget.Namespace, lbTarget.Service, lbTarget.PortName) {
				// if the service doesn't exist in kube's records, we don't create it
				// w.logger.Debugf("filtering missing service - %s", match)
				continue
			} else if !w.serviceClusterIPisSet(lbTarget.Namespace, lbTarget.Service) {
				// w.logger.Debugf("filtering service with no ClusterIP - %s", match)
				continue
			} else if !w.serviceHasValidEndpoints(lbTarget.Namespace, lbTarget.Service) {
				// w.logger.Debugf("filtering service with no Endpoints - %s", match)
				log.Warningln("service has no endpoints:", lbTarget.Namespace, lbTarget.Service)
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
