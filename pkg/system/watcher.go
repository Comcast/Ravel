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
	"strings"
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
type Watcher struct {
	sync.Mutex

	configMapNamespace string
	configMapName      string
	configKey          string

	allServices  map[string]*v1.Service
	allEndpoints map[string]*v1.Endpoints
	configMap    *v1.ConfigMap

	// client watches.
	clientset  *kubernetes.Clientset
	nodeWatch  watch.Interface
	services   watch.Interface
	endpoints  watch.Interface
	configmaps watch.Interface

	// this is the 'official' configuration
	ClusterConfig *types.ClusterConfig
	Nodes         types.NodesList

	// default listen services for vips in the vip pool
	autoSvc  string
	autoPort int

	// How long to wait to re-init watchers after a watcher error.
	// Starts at 1 second, then increments by 1 second every time
	// there's another error without an intervening successful event.
	watchBackoffDuration time.Duration

	publishChan chan *types.ClusterConfig

	ctx     context.Context
	logger  log.FieldLogger
	metrics watcherMetrics
}

// NewWatcher creates a new Watcher struct, which is used to watch services, endpoints, and more
func NewWatcher(ctx context.Context, kubeConfigFile, cmNamespace, cmName, configKey, lbKind string, autoSvc string, autoPort int, logger log.FieldLogger) (*Watcher, error) {

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

	w := &Watcher{
		ctx: ctx,

		clientset: clientset,

		configMapNamespace: cmNamespace,
		configMapName:      cmName,
		configKey:          configKey,

		allServices:  map[string]*v1.Service{},   // map of namespace/service to services
		allEndpoints: map[string]*v1.Endpoints{}, // map of namespace/service:port to endpoints

		autoSvc:  autoSvc,
		autoPort: autoPort,

		publishChan: make(chan *types.ClusterConfig),

		logger:  logger.WithFields(log.Fields{"module": "watcher"}),
		metrics: NewWatcherMetrics(lbKind, configKey),
	}
	if err := w.initWatch(); err != nil {
		log.Errorln("Failed to init watcher with error:", err)
		return nil, err
	}
	go w.watches()
	go w.watchPublish()
	go w.debugWatcher() // DEBUG

	return w, nil
}

// debugWatcher - DEBUG is used to output debug information
func (w *Watcher) debugWatcher() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		<-t.C

		for k, v := range w.allEndpoints {
			// k == endpoints.ObjectMeta.Namespace + "/" + endpoints.ObjectMeta.Name
			svcName := "egreer200/graceful-shutdown-app"
			if k == svcName {
				for _, s := range v.Subsets {
					var validIPs []string
					for _, a := range s.Addresses {
						validIPs = append(validIPs, a.IP)
					}
					log.Debugln("debug-watcher: subset addresses for service graceful-shutdown-app:", strings.Join(validIPs, ","))
				}
			}
		}

		// check clusterConfig for issues with being nil
		if w.ClusterConfig == nil {
			log.Debugln("debug-watcher: w.ClusterConfig is nil")
			return
		}

		log.Debugln("debug-watcher: w.ClusterConfig has", len(w.ClusterConfig.Config), "service IPs configured")
		log.Debugln("debug-watcher: w.ClusterConfig has", len(w.Nodes), "nodes configured")
		// log.Debugln("debug-watcher: w.ClusterConfig has", len(w.ClusterConfig.VIPPool), "VIPs configured")
		log.Debugln("debug-watcher: watcher has", len(w.ClusterConfig.Config), "IPv4 IPs configured and", len(w.ClusterConfig.Config6), "IPv6 IPs configured")

		// output the number of endpoints on all our nodes
		for _, n := range w.Nodes {
			log.Debugln("debug-watcher:", n.Name, "has", len(n.Endpoints), "endpoints configured")
		}
	}
}

func (w *Watcher) stopWatch() {
	w.logger.Info("stopping all watches")
	w.nodeWatch.Stop()
	w.services.Stop()
	w.endpoints.Stop()
	w.configmaps.Stop()
}

func (w *Watcher) initWatch() error {
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

	configmapListWatcher := cache.NewListWatchFromClient(w.clientset.CoreV1().RESTClient(), "configmaps", "platform-load-balancer", fields.Everything())
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
func (w *Watcher) Services() map[string]*v1.Service {
	w.Lock()
	defer w.Unlock()

	out := map[string]*v1.Service{}
	for k, v := range w.allServices {
		out[k] = v
	}
	return out
}

// resetWatch attempts to bootstrap initWatch indefinitely.
func (w *Watcher) resetWatch() error {

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
func (w *Watcher) watches() {

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
			svc := evt.Object.(*v1.Service)
			log.Debugln("watcher: services chan got an event:", svc.Name, evt.Type)

			// DEBUG - trace 5016 entries
			if strings.Contains(svc.String(), "5016") {
				log.Debugln("DEBUG - found 5016 in service channel update from kube-api:", evt)
			}
			if strings.Contains(svc.String(), "graceful-shutdown-app") {
				log.Debugln("DEBUG - found 5016 in service channel update from kube-api:", evt)
			}

			w.processService(evt.Type, svc.DeepCopy())

		case evt, ok := <-w.endpoints.ResultChan():
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

			// if the endpoint modification was for kube-controller-manager or kube-scheduler, skip it.
			// these two spam updates constantly
			ep := evt.Object.(*v1.Endpoints)
			log.Debugln("watcher: endpoints chan got an event:", ep.Name, evt.Type)
			if ep.Name == "kube-controller-manager" && ep.Namespace == "kube-system" {
				log.Debugln("watcher: skipped endpoints from kube-controller-manager")
				continue
			}
			if ep.Name == "kube-scheduler" && ep.Namespace == "kube-system" {
				log.Debugln("watcher: skipped endpoints from kube-scheduler")
				continue
			}
			// log.Debugln("watcher: endpoints chan got an event:", evt)

			// DEBUG - trace 5016 entries
			if strings.Contains(ep.String(), "graceful-shutdown-app") {
				log.Debugln("DEBUG - found 5016 service in endpoints channel update from kube-api:", evt)
			}

			w.watchBackoffDuration = 0
			epUpdates++
			w.metrics.WatchData("endpoints")
			// w.logger.Debugf("got new endpoints from result chan")
			w.processEndpoint(evt.Type, ep.DeepCopy())

		case evt, ok := <-w.configmaps.ResultChan():
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
			log.Debugln("watcher: configmaps chan got an event:", cm.Name, evt.Type)
			w.processConfigMap(evt.Type, cm.DeepCopy())

		case evt, ok := <-w.nodeWatch.ResultChan():
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
			log.Debugln("watcher: nodeWatch chan got an event:", n.Name, evt.Type)

			// DEBUG - trace 5016 entries
			if strings.Contains(n.String(), "10.131.153.81") || strings.Contains(n.String(), "10.131.153.76") {
				log.Debugln("DEBUG - found 5016 node in node channel update from kube-api:", evt)
			}

			w.processNode(evt.Type, n.DeepCopy())

		case <-metricsUpdateTicker.C:

			w.metrics.WatchBackoffDuration(w.watchBackoffDuration)

			w.logger.WithFields(log.Fields{
				"total":     totalUpdates,
				"nodes":     nodeUpdates,
				"services":  svcUpdates,
				"endpoints": epUpdates,
				"configmap": cmUpdates,
			}).Infof("watcher: watch summary")
			totalUpdates, nodeUpdates, svcUpdates, epUpdates, cmUpdates = 0, 0, 0, 0, 0
		}
		// increment total only if the watchers didn't expire
		totalUpdates++
		// log.Debugln("watcher: update count is now:", totalUpdates)

		if w.configMap == nil {
			w.logger.Warnf("configmap is nil. skipping publication")
			continue
		}

		// Build a new cluster config and publish it, maybe
		modified, newConfig, err := w.buildClusterConfig()
		if err != nil {
			w.metrics.WatchClusterConfig("error")
			w.logger.Errorf("watcher: error building cluster config. %v", err)
		}
		if !modified {
			w.metrics.WatchClusterConfig("noop")
			// w.logger.Debug("watcher: cluster config not modified")
		} else {
			// if the cluster config is nil, don't use it - that would wipe a bunch of rules out
			if newConfig == nil {
				log.Errorln("watcher: a nil clusterConfig was returned from w.buildClusterConfig(), but it was also shown as modified.")
				continue
			}

			w.metrics.WatchClusterConfig("publish")
			w.logger.Debug("watcher: publishing new cluster config")

			// DEBUG - call out a trace entry if a port with 5016 is passed through here
			for _, v := range newConfig.Config {
				if v["5016"] != nil {
					log.Debugln("watcher: a config with a 5016 entry was passed to the CLUSTER config publish chan")
				}
			}

			// count the old port configs
			var oldPortConfigCount int
			if w.ClusterConfig != nil {
				for _, portConfigs := range w.ClusterConfig.Config {
					oldPortConfigCount += len(portConfigs)
				}
			}
			// count the new port configs
			var newPortConfigCount int
			for _, portConfigs := range newConfig.Config {
				newPortConfigCount += len(portConfigs)
			}
			log.Println("watcher: cluster config was changed. Old port config count:", oldPortConfigCount, "New port config count:", newPortConfigCount)

			w.publishChan <- newConfig
		}

		// Here, do the nodes workflow and publish it definitely
		// Compute a new set of nodes and node endpoints. Compare that set of info to the
		// set of info that was last transmitted.  If it changed, publish it.
		nodes, err := w.buildNodeConfig()
		if err != nil {
			w.logger.Errorf("watcher: error building node config: %v", err)
			continue
		}

		// DEBUG - call out a trace entry if a port with 5016 is passed through here
		// for _, v := range nodes {
		// 	for _, ep := range v.Endpoints {
		// 		if strings.Contains("graceful-shutdown-app", ep.Service) {
		// 			log.Debugln("watcher: a config with a 5016 entry was passed to the NODE config publish func")
		// 		}
		// 	}
		// }

		// w.logger.Infof("watcher: publishing node config")
		w.publishNodes(nodes)
	}
}

// convertKubeEndpointToRavelEndpoints converts a kubernetes endpoint to a ravel endpoint.
func convertKubeEndpointToRavelEndpoint(kubeEndpoints *v1.Endpoints) types.Endpoints {

	// make a new endpoints collection and populat the metadata
	newEndpoints := types.Endpoints{
		EndpointMeta: types.EndpointMeta{
			Namespace: kubeEndpoints.Namespace,
			Service:   kubeEndpoints.Name,
		},
	}

	// loop over every incoming kube endpoint and create a subset out of it
	for _, subset := range kubeEndpoints.Subsets {
		newSubset := types.NewSubset(subset)
		newEndpoints.Subsets = append(newEndpoints.Subsets, newSubset)
	}

	return newEndpoints
}

// buildNodeConfig outputs an array of nodes containing a per-node, filtered
// array of endpoints for the node.  To get there it needs to eliminate irrelevant
// endpoints, generate an intermediate set of endpoints pertinent to each node,
// and assemble it all into an array.
func (w *Watcher) buildNodeConfig() (types.NodesList, error) {

	// if the clusterConfig is nil for the watcher, we can't do anything
	if w.ClusterConfig == nil {
		// w.logger.Infof("w.ClusterConfig %p, len allEndpoints %d", w.ClusterConfig, len(w.allEndpoints))
		log.Errorln("watcher: error in buildNodeConfig().  Tried to build NodeList, but w.ClusterConfig was nil")
		return types.NodesList{}, nil
	}

	// if all endpoints are empty then throw an error. we can't publish this
	if len(w.allEndpoints) == 0 {
		err := fmt.Errorf("watcher: error in buildNodeConfig().  Tried to build NodeList, but w.allEndpoints was empty")
		return types.NodesList{}, err
	}

	if len(w.Nodes) == 0 {
		err := fmt.Errorf("watcher: error in buildNodeConfig().  Tried to build NodeList, but w.Nodes was empty")
		return types.NodesList{}, err
	}

	// make a map for all nodes known to the watcher to prevent dupes
	nodeMap := make(map[string]types.Node)
	for _, n := range w.Nodes {
		nodeMap[n.Name] = n
	}

	// loop over all endpoints and sort them into our nodes
	for _, endpoint := range w.allEndpoints { // Kubernetes *v1.Endpoint
		// each endpoint has subsets that need iterated on
		for _, subset := range endpoint.Subsets {
			var owningNodeName string // the node that this subset should be sorted to
			// each subset has addresses to be iterated on.  We ignore the NotReadyAddresses property.
			for _, addr := range subset.Addresses {
				// check if this address's node name is in our nodeList map.  If not,
				// skip it until we learn about this node
				owningNode, ok := nodeMap[*addr.NodeName]
				if !ok {
					log.Warningln("watcher: buildNodeConfig() skipped endpoint", addr.IP, "for node", *addr.NodeName, "because no node of this name is known yet")
					continue
				}

				// we have found the owner of this subset
				owningNodeName = owningNode.Name
				break

			}

			// if we found an owningNodeName, then lets put this endpoint in it
			if owningNodeName != "" {
				// convert the kubernetes endpoing into a types.Node (why on earth did someone use a types.Endpoints?!?)
				newEndpoint := convertKubeEndpointToRavelEndpoint(endpoint)

				// fetch the owning node from our node map, append this new endpoint, and set it back
				owningNode := nodeMap[owningNodeName]
				owningNode.Endpoints = append(nodeMap[owningNodeName].Endpoints, newEndpoint)
				nodeMap[owningNodeName] = owningNode
			}
		}
	}

	// convert the nodeList map into a types.NodeList.  Sort all the subsets
	// and then sort the node list at the end as well
	var nodeList types.NodesList
	for _, n := range nodeList {
		n.SortConstituents()
		nodeList = append(nodeList, n)
	}
	sort.Sort(nodeList)

	return nodeList, nil

	// The following was the original logic that was replaced by the stuff above
	// nodes := w.Nodes.Copy()

	// // Index into w.Nodes by node.Name.
	// // Code later assumes node.Name == subset's *address.NodeName
	// // so that we can match a v1.EndpointSubset to a types.Node
	// nodeIndexes := make(map[string]int)
	// for nodeIndex, node := range w.Nodes {
	// 	nodeIndexes[node.Name] = nodeIndex
	// }

	// // AddressTotals captures the total # of address records for any given
	// // namespace/service:port triplet.  This, in combination with the pod totals
	// // on a node, can determine the appropriate ratio of traffic that a node should
	// // receive for a given service. These ratios are used by the ipvs master in order
	// // to capture traffic for local services, outside of ipvs, when the master is not
	// // running in an isolated context.
	// addressTotals := map[string]int{}

	// seenAlready := make(map[string]bool)
	// for _, ep := range w.allEndpoints { // *v1.Endpoint
	// 	keyprefix := ep.Namespace + "/" + ep.Name + "/"
	// 	for _, subset := range ep.Subsets { // *v1.EndpointSubset

	// 		for _, port := range subset.Ports {
	// 			ident := types.MakeIdent(ep.Namespace, ep.Name, port.Name)
	// 			addressTotals[ident] += len(subset.Addresses)
	// 		}

	// 		for _, address := range subset.Addresses { // *v1.Address
	// 			if address.NodeName != nil && *address.NodeName != "" {
	// 				addresskey := keyprefix + *address.NodeName + ":"
	// 				naddress := []types.Address{
	// 					{PodIP: address.IP, NodeName: *address.NodeName, Kind: address.TargetRef.Kind},
	// 				}
	// 				nsubset := types.Subset{Addresses: naddress}

	// 				portkey := addresskey + ","
	// 				for _, port := range subset.Ports {
	// 					nsubset.Ports = append(nsubset.Ports, types.Port{Name: port.Name, Port: int(port.Port), Protocol: string(port.Protocol)})
	// 					portkey += port.Name + ","
	// 				}

	// 				if _, ok := seenAlready[portkey]; ok {
	// 					// This service has more than 1 pod on a node.
	// 					// Add this subset to an existing endpoint for the node
	// 					if idx, ok := nodeIndexes[*address.NodeName]; ok {
	// 						for epIdx, endp := range nodes[idx].Endpoints {
	// 							if endp.Namespace == ep.Namespace && endp.Service == ep.Name {
	// 								// Should only be a single Subset of the endpoint
	// 								nodes[idx].Endpoints[epIdx].Subsets[0].Addresses = append(nodes[idx].Endpoints[epIdx].Subsets[0].Addresses, naddress...)
	// 							}
	// 						}
	// 					} // *address.NodeName doesn't match an index into nodes[] Is this a huge problem?
	// 					continue
	// 				}
	// 				// Some work does get thrown away (nsubset) if more than 1 pod of a service
	// 				// runs on a single node. Better than looking through subset.Ports twice

	// 				seenAlready[portkey] = true

	// 				var nep types.Endpoints
	// 				nep.Namespace = ep.Namespace
	// 				nep.Service = ep.Name
	// 				nep.Subsets = append(nep.Subsets, nsubset)

	// 				if idx, ok := nodeIndexes[*address.NodeName]; ok {
	// 					nodes[idx].Endpoints = append(nodes[idx].Endpoints, nep)
	// 				} // not sure how serious the "else" is here
	// 			}
	// 		}
	// 	}
	// }

	// sort.Sort(nodes)
	// for idx := range nodes {
	// 	nodes[idx].SortConstituents()
	// 	nodes[idx].SetTotals(addressTotals)
	// }

	// return nodes, nil
}

func (w *Watcher) watchPublish() {
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

			// if we get a nil for some reason, just continue on
			if c == nil {
				log.Warningln("watcher: watchPublish skipped a nil cluster config")
				continue
			}

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
					// if we get a nil for some reason, just continue on
					if c == nil {
						log.Warningln("watcher: watchPublish skipped a nil cluster config while batching")
						continue
					}

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

func (w *Watcher) publish(cc *types.ClusterConfig) {
	startTime := time.Now()
	defer log.Debugln("watcher: publish took", time.Since(startTime), "to complete")

	w.Lock()
	defer w.Unlock()

	log.Debugln("watcher: publishing new cluster config with", len(cc.Config), "IPv4 addresses and", len(cc.Config6), "IPv6 addresses")
	w.ClusterConfig = cc

	// generate a new full config record
	b, _ := json.Marshal(w.ClusterConfig)
	sha := sha1.Sum(b)
	w.metrics.ClusterConfigInfo(base64.StdEncoding.EncodeToString(sha[:]), string(b))

	// set the new cluster config on the watcher
	log.Infoln("watcher: set new clusterConfig with", len(cc.Config), "ipv4 configs and", len(cc.Config6), "ipv6 configs")
	w.ClusterConfig = cc
}

func (w *Watcher) publishNodes(nodes types.NodesList) {
	// startTime := time.Now()
	// log.Debugln("watcher: publishNodes running")
	// defer log.Debugln("watcher: publishNodes completed in", time.Since(startTime))

	w.Lock()
	defer w.Unlock()

	// set the published nodes on the watcher
	log.Infoln("watcher: set new node config with", len(nodes), "nodes")
	w.Nodes = nodes
}

// generates a new ClusterConfig object, compares it to the existing, and if different,
// mutates the state of watcher with the new value. it returns a boolean indicating whether
// the cluster state was changed, and an error
func (w *Watcher) buildClusterConfig() (bool, *types.ClusterConfig, error) {

	// newConfig represents what is coming directly from the 'green' key in the k8s configmap
	newConfig, err := w.extractConfigKey(w.configMap)
	if err != nil {
		return false, nil, err
	}
	// if the raw config is blank, just ignore it and throw a warning
	if newConfig == nil {
		log.Warningln("watcher: w.buildClusterConfig() generated a nil rawConfig")
		return false, nil, nil
	}

	log.Debugln("watcher: buildClusterConfig newConfig has", len(newConfig.Config), "configurations after extractConfigKey")

	// Update the config to eliminate any services that do not exist
	if err := w.filterConfig(newConfig); err != nil {
		return false, nil, err
	}
	log.Debugln("watcher: buildClusterConfig newConfig has", len(newConfig.Config), "configurations after w.filterConfig")

	// Update the config to add the default listeners to all of the vips in the bip pool.
	if err := w.addListenersToConfig(newConfig); err != nil {
		return false, nil, err
	}
	log.Debugln("watcher: buildClusterConfig newConfig has", len(newConfig.Config), "configurations after w.addListenersToConfig")

	// determine if the config has changed. if it has not, then we just return
	if !w.hasConfigChanged(w.ClusterConfig, newConfig) {
		return false, nil, nil
	}

	// existingJSON, err := json.Marshal(w.ClusterConfig)
	// if err != nil {
	// 	log.Errorln("failed to marshal existing json for debug display:", err)
	// }
	// newJSON, err := json.Marshal(w.ClusterConfig)
	// if err != nil {
	// 	log.Errorln("failed to marshal new json for debug display:", err)
	// }
	// println("watcher: existing config JSON:", string(existingJSON))
	// println("watcher: new config JSON:", string(newJSON))

	return true, newConfig, nil
}

// hasConfigChanged determines if the cluster configuration has actually changed
func (w *Watcher) hasConfigChanged(currentConfig *types.ClusterConfig, newConfig *types.ClusterConfig) bool {

	// if both configs are nil, we consider them as unchanged
	if currentConfig == nil && newConfig == nil {
		log.Warningln("watcher: currentConfig and newConfig were both nil")
		return false
	}

	// if either configs have a nil (but not both), we decide things have changed
	if currentConfig == nil {
		log.Warningln("watcher: currentConfig was nil, so config has changed")
		return true
	}
	if newConfig == nil {
		log.Warningln("watcher: newConfig was nil, and the config has changed")
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
		log.Infoln("watcher: Config value count has changed from", len(currentConfig.Config), "to", len(newConfig.Config))
		return true
	}

	for currentKey, currentValue := range currentConfig.Config {
		for currentPortMapKey, currentPortMapValue := range currentValue {

			// ensure the newConfig isn't holding some nils
			if newConfig.Config[currentKey] == nil && currentValue != nil {
				log.Infoln("watcher:", currentKey, "has changed to a nil from a value")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey] == nil && currentPortMapValue != nil {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "has changed to a nil from a value")
				return true
			}

			// check the individual values for changes
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
			// this is disabled because flags can't be applied after a rule is created
			// if newConfig.Config[currentKey][currentPortMapKey].IPVSOptions.Flags != currentPortMapValue.IPVSOptions.Flags {
			// 	log.Infoln("watcher:", currentKey, currentPortMapKey, "IPVS Flags have changed:", newConfig.Config[currentKey][currentPortMapKey].IPVSOptions.Flags, "vs", currentPortMapValue.IPVSOptions.Flags)
			// 	return true
			// }
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

			// ensure the newConfig isn't holding some nils
			if newConfig.Config[currentKey] == nil && currentValue != nil {
				log.Infoln("watcher:", currentKey, "has changed to a nil from a value")
				return true
			}
			if newConfig.Config[currentKey][currentPortMapKey] == nil && currentPortMapValue != nil {
				log.Infoln("watcher:", currentKey, currentPortMapKey, "has changed to a nil from a value")
				return true
			}

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
			// this is disabled because flags can't be applied once a rule is created
			// if newConfig.Config6[currentKey][currentPortMapKey].IPVSOptions.Flags != currentPortMapValue.IPVSOptions.Flags {
			// 	log.Infoln("watcher:", currentKey, currentPortMapKey, "config6 IPVS Flags have changed")
			// 	return true
			// }
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

	// if currentConfig.IPV6 == nil || newConfig.IPV6 == nil {
	// 	log.Warningln("watcher: IPV6 was empty on new or current config")
	// 	return false
	// }

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

func (w *Watcher) processService(eventType watch.EventType, service *v1.Service) {
	w.Lock()
	defer w.Unlock()

	if eventType == "ERROR" {
		log.Errorln("watcher: got an error event type from a watcher while processing service")
		return
	}

	// first, set the value of w.service
	identity := service.ObjectMeta.Namespace + "/" + service.ObjectMeta.Name
	switch eventType {
	case "ADDED", "MODIFIED":
		log.Debugln("watcher: service added or modified:", service.Name)
		// w.logger.Debugf("processService - ADDED")
		w.allServices[identity] = service

	case "DELETED":
		log.Debugln("watcher: service deleted:", service.Name)
		// w.logger.Debugf("processService - DELETED")
		delete(w.allServices, identity)

	default:
	}

}

func (w *Watcher) processNode(eventType watch.EventType, node *v1.Node) {
	// mutex this operation
	w.Lock()
	defer w.Unlock()

	if eventType == "ERROR" {
		log.Errorln("watcher: got an eventType of ERROR with the following information:", node)
		return
	}

	// ensure the watcher's node list is not blank
	if w.Nodes == nil {
		w.Nodes = types.NodesList{}
	}

	// if a node is added, append to the array
	// if a node is modified, iterate and search the array for the node, then replace the record
	// if a node is deleted, iterate and search the array for the node, then remove the record
	switch eventType {
	case "ADDED", "MODIFIED":
		log.Infoln("watcher: node added or modified:", node.Name)
		// w.logger.Debugf("processNode - %s - %v", eventType, node)
		var foundExistingNode bool
		for i, existing := range w.Nodes {
			if existing.Name == node.Name {
				log.Debugln("watcher: updated node:", node.Name)
				w.Nodes[i] = types.NewNode(node)
				foundExistingNode = true
				break
			}
		}
		// add the new node if it was not found already
		if !foundExistingNode {
			log.Infoln("watcher: found new node:", node.Name)
			w.Nodes = append(w.Nodes, types.NewNode(node))
		}
	case "DELETED":
		for i, existing := range w.Nodes {
			if existing.Name == node.Name {
				log.Infoln("watcher: node deleted:", node.Name)
				w.Nodes = append(w.Nodes[:i], w.Nodes[i+1:]...)
			}
		}
	}

}

func (w *Watcher) processConfigMap(eventType watch.EventType, configmap *v1.ConfigMap) {
	// mutex this operation
	w.Lock()
	defer w.Unlock()

	if eventType == "ERROR" {
		log.Errorln("error: got error event while watching configmap", configmap.Name)
		return
	}

	// ensure that the configmap value is correct
	if configmap.Name != w.configMapName {
		return
	}

	log.Infoln("watcher: detected new or modified configmap:", configmap.Namespace, configmap.Name)
	w.configMap = configmap
}

func (w *Watcher) processEndpoint(eventType watch.EventType, endpoints *v1.Endpoints) {
	if eventType == "ERROR" {
		log.Errorln("watcher: got an ERROR event type from the endpoint watcher:", endpoints)
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
		// DEBUG
		if endpoints.ObjectMeta.Name == "graceful-shutdown-app" {
			log.Debugln("watcher: got a 5016 service endpoint message of ADDED. Subsets ADDED:", endpoints.Subsets)
		}
		log.Debugln("watcher: endpoints added:", endpoints.Name)
		// w.logger.Debugf("processEndpoint - ADDED")
		w.allEndpoints[identity] = endpoints

	case "MODIFIED":
		// DEBUG
		if endpoints.ObjectMeta.Name == "graceful-shutdown-app" {
			log.Debugln("watcher: got a 5016 service endpoint message of MODIFIED. Subsets MODIFIED:", endpoints.Subsets)
		}
		log.Debugln("watcher: endpoints modified:", endpoints.Name)
		// w.logger.Debugf("processEndpoint - MODIFIED")
		w.allEndpoints[identity] = endpoints

	case "DELETED":
		// DEBUG
		if endpoints.ObjectMeta.Name == "graceful-shutdown-app" {
			log.Debugln("watcher: got a 5016 service endpoint message of DELETED. Subsets DELETED:", endpoints.Subsets)
		}
		log.Debugln("watcher: endpoints deleted:", endpoints.Name)
		// w.logger.Debugf("processEndpoint - DELETED")
		delete(w.allEndpoints, identity)

	default:
		log.Warningln("Got an unknown endpoint eventType:", eventType)
	}

	// w.logger.Debugf("processEndpoint - endpoint counts: total=%d node=%d ", len(w.allEndpoints), len(w.endpointsForNode))
}

func (w *Watcher) extractConfigKey(configmap *v1.ConfigMap) (*types.ClusterConfig, error) {
	// Unmarshal the config map, retrieving only the configuration matching the configKey
	clusterConfig, err := types.NewClusterConfig(configmap, w.configKey)
	if err != nil {
		return nil, fmt.Errorf("watcher: unable to unmarshal configmap key '%s'. %v", w.configKey, err)
	}
	if clusterConfig.Config == nil {
		return nil, fmt.Errorf("watcher: clusterConfig from types.NewClsuterconfig config is nil, but error was not set")
	}
	return clusterConfig, nil
}

// addListenersToConfig mutates the input types.ClusterConfig to add the autoSvc and autoPort
// from the watcher primary configuration, if that value is set.
func (w *Watcher) addListenersToConfig(inCC *types.ClusterConfig) error {

	// log.Debugln("unicorns: addListenersToConfig")

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
		}
	}

	// log.Debugln("unicorns: done configuring unicorns listeners")
	// w.logger.Debugf("generated cluster config: %+v", inCC)
	return nil
}

// serviceHasValidEndpoints filters out any service that does not have
// an endpoint in its endpoints list. Kubernetes will remove these services
// from the kube-proxy, and we should, too.
func (w *Watcher) serviceHasValidEndpoints(ns, svc string) bool {
	service := fmt.Sprintf("%s/%s", ns, svc)

	if w.allEndpoints[service] == nil {
		log.Debugln("watcher: skipped nil endpoints list for service", service)
	}

	if ep, ok := w.allEndpoints[service]; ok {
		// DEBUG 5016 trace
		if strings.Contains(service, "graceful") {
			log.Debugln("watcher: 5016 serviceHasValidEndpoints evaluating valid endpoints against", len(w.allEndpoints[service].Subsets), "subsets")
		}

		for _, subset := range ep.Subsets {
			if strings.Contains(service, "graceful") {
				log.Debugln("watcher: 5016 serviceHasValidEndpoints evaluating subset READY addresses:", subset.Addresses)
				log.Debugln("watcher: 5016 serviceHasValidEndpoints evaluating subset NOT READY addresses:", subset.NotReadyAddresses)
			}
			if len(subset.Addresses) != 0 {
				if strings.Contains(service, "graceful") {
					log.Debugln("watcher: 5016 serviceHasValidEndpoints determining that there ARE ready addresses")
				}
				return true
			}
		}
	}

	if strings.Contains(service, "graceful") {
		log.Debugln("watcher: 5016 serviceHasValidEndpoints evaluating NO ENDPOINTS")
	}

	return false
}

func (w *Watcher) userServiceInEndpoints(ns, svc, portName string) bool {
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
func (w *Watcher) serviceClusterIPisSet(ns, svc string) bool {

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
func (w *Watcher) filterConfig(inCC *types.ClusterConfig) error {
	if inCC == nil {
		return fmt.Errorf("watcher: filterConfig can't run because the passed in cluster config was nil")
	}

	newConfig := map[types.ServiceIP]types.PortMap{}

	// track how many ports are removed for filtering reasons
	var preFilterCount int
	var filteredPorts []string
	preFilterCount = len(inCC.Config)

	// walk the input configmap and check for matches.
	// if no match is found, continue. if a match is found, add the entire portMap back into the config
	for lbVIP, portMap := range inCC.Config {
		for port, lbTarget := range portMap {
			// check for a match!
			// match := fmt.Sprintf("%s/%s:%s", lbTarget.Namespace, lbTarget.Service, lbTarget.PortName)
			if !w.userServiceInEndpoints(lbTarget.Namespace, lbTarget.Service, lbTarget.PortName) {
				// if the service doesn't exist in kube's records, we don't create it
				// DEBUG
				if strings.Contains(lbTarget.Service, "graceful-shutdown-app") {
					log.Debugln("watcher: 5016 filtering service not found in endpoints from clusterconfig:", lbTarget.Namespace, lbTarget.Service)
				}
				if lbTarget.PortName == "8081" {
					log.Debugln("watcher: filtering 8081 service not found in endpoints from clusterconfig:", lbTarget.Namespace, lbTarget.Service, lbTarget.PortName)
				}
				filteredPorts = append(filteredPorts, lbTarget.Namespace+"/"+lbTarget.Service+":"+port)
				continue
			}

			if !w.serviceClusterIPisSet(lbTarget.Namespace, lbTarget.Service) {
				// DEBUG
				if strings.Contains(lbTarget.Service, "graceful-shutdown-app") {
					log.Debugln("watcher: 5016 filtering service with no clusterIP set from clusterconfig:", lbTarget.Namespace, lbTarget.Service)
				}
				if lbTarget.PortName == "8081" {
					log.Debugln("watcher: filtering 8081 service for no cluster ip set from clusterconfig:", lbTarget.Namespace, lbTarget.Service, lbTarget.PortName)
				}
				filteredPorts = append(filteredPorts, lbTarget.Namespace+"/"+lbTarget.Service+":"+port)
				continue
			}

			if !w.serviceHasValidEndpoints(lbTarget.Namespace, lbTarget.Service) {
				// w.logger.Debugf("filtering service with no Endpoints - %s", match)
				// log.Warningln("service has no endpoints:", lbTarget.Namespace, lbTarget.Service)

				// DEBUG
				if strings.Contains(lbTarget.Service, "graceful-shutdown-app") {
					log.Debugln("watcher: 5016 filtering service without any endpoints from clusterconfig:", lbTarget.Namespace, lbTarget.Service)
				}
				if lbTarget.PortName == "8081" {
					log.Debugln("watcher: filtering 8081 service has invalid endpoints endpoints from clusterconfig:", lbTarget.Namespace, lbTarget.Service, lbTarget.PortName)
				}
				filteredPorts = append(filteredPorts, lbTarget.Namespace+"/"+lbTarget.Service+":"+port)
				continue
			}

			// make a new port map and put itin the lbVIP config
			newPortMap := types.PortMap{}
			newPortMap[port] = lbTarget

			newConfig[lbVIP] = newPortMap
			break
		}
	}

	// display how many ports were filtered and what they were
	postFilterCount := len(newConfig)
	filterDifference := preFilterCount - postFilterCount
	log.Debugln("watcher: filterConfig filtered", filterDifference, "ports out of the cluster config:", strings.Join(filteredPorts, ","))

	// set the new filtered config on top of the original
	inCC.Config = newConfig

	return nil
}
