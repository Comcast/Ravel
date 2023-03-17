package watcher

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
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
	sync.RWMutex

	ConfigMapNamespace string
	ConfigMapName      string
	ConfigKey          string

	AllServices   map[string]*v1.Service
	AllEndpoints  map[string]*v1.Endpoints
	AllPods       map[string]*v1.Pod
	AllPodsByNode map[string][]*v1.Pod // map of node name to pods on the node
	ConfigMap     *v1.ConfigMap

	// client watches.
	clientset  *kubernetes.Clientset
	nodeWatch  watch.Interface
	services   watch.Interface
	endpoints  watch.Interface
	configmaps watch.Interface
	podChan    watch.Interface

	// this is the 'official' configuration
	ClusterConfig *types.ClusterConfig
	Nodes         []*v1.Node

	// default listen services for vips in the vip pool
	AutoSvc  string
	AutoPort int

	// How long to wait to re-init watchers after a watcher error.
	// Starts at 1 second, then increments by 1 second every time
	// there's another error without an intervening successful event.
	watchBackoffDuration time.Duration

	publishChan chan *types.ClusterConfig

	ctx     context.Context
	logger  log.FieldLogger
	metrics WatcherMetrics
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

		ConfigMapNamespace: cmNamespace,
		ConfigMapName:      cmName,
		ConfigKey:          configKey,

		AllServices:   map[string]*v1.Service{},   // map of namespace/service to services
		AllEndpoints:  map[string]*v1.Endpoints{}, // map of namespace/service:port to endpoints
		AllPods:       map[string]*v1.Pod{},       // map of pod name to spec
		AllPodsByNode: map[string][]*v1.Pod{},     // map of node name to pods

		AutoSvc:  autoSvc,
		AutoPort: autoPort,

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
	go w.ingestPodWatchEvents()
	// go w.debugWatcher()
	go w.StartDebugWebServer()

	return w, nil
}

func (w *Watcher) deleteAllPods (podLookupKey string) {
	w.Lock()
	defer w.Unlock()
	delete(w.AllPods, podLookupKey)
}

func (w *Watcher) setAllPods(key string, p *v1.Pod) {
	w.Lock()
	defer w.Unlock()
	w.AllPods[key] = p
}

func (w *Watcher) getAllPodsByNode(name string) []*v1.Pod {
	w.Lock()
	defer w.Unlock()
	return w.AllPodsByNode[name]
}

func (w *Watcher) setAllPodsByNode(name string, val []*v1.Pod) {
	w.Lock()
	defer w.Unlock()
	w.AllPodsByNode[name] = val
}

// StartDebugWebService starts an http server for pprof and other debugging
func (w *Watcher) StartDebugWebServer() {
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/watcherDump", func(res http.ResponseWriter, req *http.Request) {
			log.Infoln("watcher debug web service handling call to /watcherDump")
			b, err := json.MarshalIndent(w, "", "  ")
			if err != nil {
				log.Errorln("error serving debug output:", err)
			}
			res.Write(b)
		})
		log.Println("debug web server started on port 9999")
		err := http.ListenAndServe("0.0.0.0:9999", mux)
		log.Errorln("error with debug web server:", err)
	}()
}

// ServiceDefinitionCount returns the total number of PortConfig structs that exist currently in the
// watcher's known configuration
func (w *Watcher) ServiceDefinitionCount() int {
	if w.ClusterConfig == nil {
		return 0
	}

	var count int
	w.RLock()
	defer w.RUnlock()
	for _, portMap := range w.ClusterConfig.Config {
		count += len(portMap)
	}
	return count
}

// ConfigIPCount returns the number of v4 IPs in the cluster config
func (w *Watcher) ConfigIPCount() int {
	if w.ClusterConfig == nil {
		return 0
	}
	w.RLock()
	defer w.RUnlock()
	return len(w.ClusterConfig.Config)
}

// ConfigIPCount6 returns the number of v6 IPs in the cluster config
func (w *Watcher) ConfigIPCount6() int {
	if w.ClusterConfig == nil {
		return 0
	}
	w.RLock()
	defer w.RUnlock()
	return len(w.ClusterConfig.Config6)
}

// VIPPoolCount returns the number of VIPs configured in total
func (w *Watcher) VIPPoolCount() int {
	if w.ClusterConfig == nil {
		return 0
	}
	w.RLock()
	defer w.RUnlock()
	return len(w.ClusterConfig.VIPPool)
}

// EndpointCount returns the number of endpoints known to the watcher
func (w *Watcher) EndpointCount() int {
	w.RLock()
	defer w.RUnlock()
	return len(w.AllEndpoints)
}

// ServiceCount returns the number of services known to the watcher
func (w *Watcher) ServiceCount() int {
	w.RLock()
	defer w.RUnlock()
	return len(w.AllServices)
}

// SubsetIPsForService returns the subset IPs that are currently cached in the watcher for
// the specified service
func (w *Watcher) SubsetIPsForService(serviceName string, namespace string) []string {
	var validSubsetIPs []string
	w.RLock()
	defer w.RUnlock()
	for _, v := range w.AllEndpoints {
		// k == endpoints.ObjectMeta.Namespace + "/" +endpoints.ObjectMeta.Name
		if !strings.EqualFold(v.ObjectMeta.Namespace, namespace) {
			continue
		}
		if !strings.EqualFold(v.ObjectMeta.Name, serviceName) {
			continue
		}
		for _, s := range v.Subsets {
			for _, a := range s.Addresses {
				validSubsetIPs = append(validSubsetIPs, a.IP)
			}
		}
	}
	return validSubsetIPs
}

func (w *Watcher) ServiceIsConfigured(serviceName string, serviceNamespace string) bool {
	w.RLock()
	defer w.RUnlock()
	if w.ClusterConfig == nil {
		return false
	}

	for _, v := range w.ClusterConfig.Config {
		for _, sc := range v {
			if !strings.EqualFold(sc.Namespace, serviceNamespace) {
				continue
			}
			if !strings.EqualFold(sc.Service, serviceName) {
				continue
			}
			return true
		}
	}
	return false
}

// debugWatcher is used as a go routine to output debug information
func (w *Watcher) debugWatcher() {
	t := time.NewTicker(time.Second * 5)
	defer t.Stop()
	for {
		<-t.C

		// check clusterConfig for issues with being nil
		if w.ClusterConfig == nil {
			log.Debugln("debug-watcher: w.ClusterConfig is nil")
			continue
		}

		// if w.ServiceIsConfigured("vsg-ml-inference-consumer", "nginx") {
		// 	log.Debugln("debug-watcher: w.ClusterConfig.Config DOES have service vsg-ml-inference-consumer")
		// } else {
		// 	log.Debugln("debug-watcher: w.ClusterConfig.Config does NOT have service vsg-ml-inference-consumer")
		// }

		// log.Debugln("debug-watcher: w.ClusterConfig has", len(w.ClusterConfig.Config), "service IPs configured")
		log.Debugln("debug-watcher: w.ClusterConfig has", w.ConfigIPCount(), "IPv4 IPs configured and", w.ConfigIPCount6(), "IPv6 IPs configured")
		log.Debugln("debug-watcher: w.ClusterConfig has", len(w.Nodes), "nodes configured")
		log.Debugln("debug-watcher: w.ClusterConfig has", w.ServiceCount(), "services configured")
		log.Debugln("debug-watcher: w.ClusterConfig has", w.EndpointCount(), "endpoints configured")
		// log.Debugln("debug-watcher: w.ClusterConfig has", len(w.ClusterConfig.VIPPool), "VIPs configured")

		// // output the number of endpoints on all our nodes
		// for _, n := range w.Nodes {
		// 	// grab all the endpoints for our graceful-shutdown-app debug service
		// 	log.Debugln("debug-watcher: node", n.Name, "has", len(n.EndpointAddresses), "endpoint addresses")
		// }
	}
}

func (w *Watcher) stopWatch() {
	w.logger.Info("stopping all watches")
	w.nodeWatch.Stop()
	w.services.Stop()
	w.endpoints.Stop()
	w.configmaps.Stop()
	w.podChan.Stop()
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

	podsListWatcher := cache.NewListWatchFromClient(w.clientset.CoreV1().RESTClient(), "pods", v1.NamespaceAll, fields.Everything())
	_, _, podChan, _ := watchtools.NewIndexerInformerWatcher(podsListWatcher, &v1.Pod{})
	w.podChan = podChan

	// w.services = services
	// w.endpoints = endpoints
	// w.configmaps = configmaps
	// w.nodeWatch = nodes
	w.metrics.WatchInit(time.Since(start))
	return nil
}

// ingestPodWatchEvents maintains a cache of all pods in the cluster
func (w *Watcher) ingestPodWatchEvents() {
	log.Debugln("watcher: ingestPodWatchEvents: starting up ...")
	for podEvent := range w.podChan.ResultChan() {
		// log.Debugln("watcher: ingestPodWatchEvents: got an event from pod channel")

		if podEvent.Object == nil {
			log.Debugln("watcher: podChan event object was nil and skipped")
			continue
		}
		// if the endpoint modification was for kube-controller-manager or kube-scheduler, skip it.
		// these two spam updates constantly
		p, ok := podEvent.Object.(*v1.Pod)
		if !ok {
			log.Errorln("watcher: the pod update channel got an update, but the object was not a *v1.Pod so it was skipped")
			continue
		}
		podLookupKey := p.Namespace + "/" + p.Name

		// depending on the update type, change the contents of the pods map
		// log.Debugln("watcher: ingestPodWatchEvents: waiting for mutex lock...")
		w.Lock()
		// log.Debugln("watcher: ingestPodWatchEvents: got mutex lock!")

		switch podEvent.Type {
		case watch.Deleted:
			log.Debugln("watcher: ingestPodWatchEvents: deleted pod", p.Name, "from node", p.Spec.NodeName, "in namespace", p.Namespace)

			w.deleteAllPods(podLookupKey) //delete(w.AllPods, podLookupKey)

			// delete the pod from the optimized table where pods are kept by node name

			nodePods := w.getAllPodsByNode(p.Spec.NodeName)  // AllPodsByNode[p.Spec.NodeName]
			for i, np := range nodePods {
				// if the pod removed matches the one in the nodePods slice, remove it
				if np.Namespace == p.Namespace && np.Name == p.Name {
					nodePods = append(nodePods[:i], nodePods[i+1:]...)
				}
			}
			w.setAllPodsByNode(p.Spec.NodeName, nodePods)  // AllPodsByNode[p.Spec.NodeName] =  nodePods

		case watch.Added, watch.Modified:

			log.Debugln("watcher: ingestPodWatchEvents: added/modified pod", p.Name, "on node", p.Spec.NodeName, "in namespace", p.Namespace)

			// update the pod in the global all pods map
			w.setAllPods(podLookupKey, p)  //  w.AllPods[podLookupKey] = p

			// update the existing pod in the optimized node to pods map if it exists
			nodePods := w.getAllPodsByNode(p.Spec.NodeName)
			var podUpdated bool
			for i, np := range nodePods {
				if np.Namespace == p.Namespace && np.Name == p.Name {
					log.Debugln("watcher: ingestPodWatchEvents: successfully modified pod", p.Name, "on node", p.Spec.NodeName, "in namespace", p.Namespace)
					nodePods[i] = p
					podUpdated = true
				}
			}

			// if pod was not in slice, then add it in
			if !podUpdated {
				log.Debugln("watcher: ingestPodWatchEvents: successfully added pod", p.Name, "on node", p.Spec.NodeName, "in namespace", p.Namespace)
				nodePods = append(nodePods, p)
			}

			// store the updated pods slice back in the optimized node to pods map
			w.setAllPodsByNode(p.Spec.NodeName, nodePods)
			log.Debugln("watcher: ingestPodWatchEvents:", p.Spec.NodeName, "now has", len(nodePods), "pods registered to it")

		case watch.Error:
			log.Errorln("watcher: error received from the pod update channel", p)
		}

		w.Unlock()
		// log.Debugln("watcher: ingestPodWatchEvents: unlocked mutex")
	}
}

// Services documented in interface definition
func (w *Watcher) Services() map[string]*v1.Service {
	w.RLock()
	defer w.RUnlock()

	out := map[string]*v1.Service{}
	for k, v := range w.AllServices {
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
	log.Debugln("watcher: starting up watches")

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
			// log.Debugln("watcher: services chan got an event:", evt)
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
			// log.Debugln("watcher: services chan got an event:", svc.Name, evt.Type)

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
			// log.Debugln("watcher: endpoints chan got an event:", ep.Name, evt.Type)
			if ep.Name == "kube-controller-manager" && ep.Namespace == "kube-system" {
				// log.Debugln("watcher: skipped endpoints from kube-controller-manager")
				continue
			}
			if ep.Name == "kube-scheduler" && ep.Namespace == "kube-system" {
				// log.Debugln("watcher: skipped endpoints from kube-scheduler")
				continue
			}
			// log.Debugln("watcher: endpoints chan got an event:", evt)

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
			w.processConfigMap(evt.Type, cm)

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

			w.processNode(evt.Type, n.DeepCopy())

			// Compute a new set of nodes and node endpoints. Compare that set of info to the
			// set of info that was last transmitted.  If it changed, publish it.
			// log.Debugln("watcher: buildNodeConfig() building node config")
			nodes, err := w.buildNodeConfig()
			if err != nil {
				w.logger.Errorf("watcher: error building node config: %v", err)
				continue
			}

			// log.Debugln("watcher: publishing node config")
			w.publishNodes(nodes)

			// here we continue becase node changes do not require checking if the cluster config has changed
			continue

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

		if w.ConfigMap == nil {
			w.logger.Warnf("configmap is nil. skipping publication")
			continue
		}

		// Build a new cluster config and publish it if it changed
		newConfig, err := w.buildClusterConfig()
		if err != nil {
			log.Errorln("watcher: error building cluster config:", err)
			w.metrics.WatchClusterConfig("error")
		}
		// log.Debugln("watcher: buildClusterConfig returning values:", newConfig, err)

		// determine if the config has changed. if it has not, then we just return
		// if !w.HasConfigChanged(w.ClusterConfig, newConfig) {
		// w.metrics.WatchClusterConfig("noop")
		// log.Debugln("watcher: cluster config not modified")
		// continue
		// }
		// log.Infoln("watcher: cluster config has been modified")

		// log.Debugln("watcher: cluster config was modified")
		// if the cluster config is nil, don't use it - that would wipe a bunch of rules out

		w.metrics.WatchClusterConfig("publish")
		w.logger.Debug("watcher: publishing new cluster config")

		// count the old port configs
		var oldPortConfigCount int
		if w.ClusterConfig != nil {
			for _, portConfigs := range w.ClusterConfig.Config {
				oldPortConfigCount += len(portConfigs)
			}
		}
		// count the new port config count and events
		var newPortConfigCount int
		for _, portConfigs := range newConfig.Config {
			newPortConfigCount += len(portConfigs)
		}
		log.Println("watcher: cluster config was changed. Old ip count:", oldPortConfigCount, "New ip count:", newPortConfigCount)
		w.publishChan <- newConfig
	}
}

// buildNodeConfig outputs an array of nodes containing a per-node, filtered
// array of endpoints for the node.  To get there it needs to eliminate irrelevant
// endpoints, generate an intermediate set of endpoints pertinent to each node,
// and assemble it all into an array.
func (w *Watcher) buildNodeConfig() ([]*v1.Node, error) {

	// if the clusterConfig is nil for the watcher, we can't do anything
	if w.ClusterConfig == nil {
		// w.logger.Infof("w.ClusterConfig %p, len AllEndpoints %d", w.ClusterConfig, len(w.AllEndpoints))
		return []*v1.Node{}, fmt.Errorf("watcher: error in buildNodeConfig().  Tried to build NodeList, but w.ClusterConfig was nil")
	}

	// if all endpoints are empty then throw an error. we can't publish this
	if len(w.AllEndpoints) == 0 {
		return []*v1.Node{}, fmt.Errorf("watcher: error in buildNodeConfig().  Tried to build NodeList, but w.AllEndpoints was empty")
	}

	if len(w.Nodes) == 0 {
		return []*v1.Node{}, fmt.Errorf("watcher: error in buildNodeConfig().  Tried to build NodeList, but w.Nodes was empty")
	}

	w.RLock()
	defer w.RUnlock()

	// make a map for all nodes known to the watcher to prevent dupes
	nodeMap := make(map[string]*v1.Node)
	for _, n := range w.Nodes {
		nodeMap[n.Name] = n
	}

	// loop over subsets across all endpoints and sort them into our nodes
	// for _, endpoint := range w.AllEndpoints { // Kubernetes *v1.Endpoint

	// 	// look over the subsets and address to find what node owns this endpoint
	// 	for _, subset := range endpoint.Subsets {

	// 		// find the owning node of this set of subsets
	// 		for _, addr := range subset.Addresses {
	// 			if addr.NodeName == nil {
	// 				log.Warningln("watcher: skipped a subset address because the NodeName within was nil")
	// 				continue
	// 			}

	// 			// check if this address's node name is in our nodeList map.  If not,
	// 			// skip it until we learn about this node existing
	// 			owningNode, ok := nodeMap[*addr.NodeName]
	// 			if !ok {
	// 				log.Warningln("watcher: buildNodeConfig() skipped endpoint", addr.IP, "for node", *addr.NodeName, "because no node of this name is known yet")
	// 				continue
	// 			}

	// 			// if the node does not have this endpoint yet, then we add it to the list and set this node in the node map
	// 			if !w.nodeHasAddressAlready(owningNode, addr) {
	// 				// fetch the owning node from our node map, append this new endpoint, and set it back
	// 				owningNode.EndpointAddresses = append(owningNode.EndpointAddresses, addr)
	// 				log.Warningln("watcher: node", owningNode.Name, "has had the following endpoint added:", endpoint, "these endpoints are now set:", owningNode.EndpointAddresses)
	// 				w.Lock()
	// 				nodeMap[owningNode.Name] = owningNode
	// 				w.Unlock()
	// 			}
	// 		}
	// 	}
	// }

	// convert the nodeList map into a types.NodeList.  Sort all the subsets
	// and then sort the node list at the end as well
	var nodeList []*v1.Node
	for _, n := range nodeMap {
		nodeList = append(nodeList, n)
	}

	// log.Debugln("watcher: buildNodeConfig is returning", len(nodeList), "nodes")
	return nodeList, nil
}

// GetPodIPsOnNode fetches all the PodIPs for the specified service on the specified node.
func (w *Watcher) GetPodIPsOnNode(nodeName string, serviceName string, namespace string, portName string) []string {

	// fetch all the pod IPs on the node
	nodePodIPs := []string{}
	for _, p := range w.getAllPodsByNode(nodeName) {
		if len(p.Status.PodIP) > 0 {
			nodePodIPs = append(nodePodIPs, p.Status.PodIP)
		}
	}
	// log.Println("watcher: GetPodIPsOnNode: found", len(nodePodIPs), "pod IPs for node", nodeName)

	var foundIPs []string
	endpointAddresses := w.GetEndpointAddressesForService(serviceName, namespace, portName)
	// log.Println("watcher: GetPodIPsOnNode: found", len(endpointAddresses), "endpoint addresses for service", serviceName+":"+portName)
	for _, ep := range endpointAddresses {
		// ensure this endpoint address is a pod on the node in question
		for _, podIP := range nodePodIPs {
			if ep.IP == podIP {
				// log.Println("watcher: GetPodIPsOnNode: found endpoint", ep.IP, "for service", serviceName, "on node", nodeName, "with port name", portName+":", strings.Join(nodePodIPs, ","))
				foundIPs = append(foundIPs, ep.IP)
			}
		}

	}
	log.Debugln("watcher: GetPodIPsOnNode:", nodeName, "has", len(foundIPs), "for service", namespace+"/"+serviceName+":"+portName+":", strings.Join(foundIPs, ","))
	return foundIPs
}

// GetNodeServiceWeight computes the likelihood that any traffic for the
// service ends up on this particular node.
func (w *Watcher) GetLocalServiceWeight(nodeName string, namespace string, service string, portName string) float64 {

	var nodeEndpointCount float64
	var totalEndpointCount float64

	// fetch the total number of endpoints in this service
	serviceEndpoints := w.GetEndpointAddressesForService(service, namespace, portName)
	totalEndpointCount = float64(len(serviceEndpoints))

	// fetch the total number of service endpoints that this specific node has
	for _, s := range serviceEndpoints {
		if s.NodeName == nil {
			log.Warningln("watcher: service endpoint", s.Hostname, "had a nil node name")
			continue
		}
		if *s.NodeName == nodeName {
			nodeEndpointCount++
		}
	}

	// calculate the node weight based on how many local addresses it has out of all service addresses
	return nodeEndpointCount / totalEndpointCount
}

// GetEndpointAddressesForNodeAndPort fetches all the subset addresses known by the watcher
// for a specific node and service port name combination.
func (w *Watcher) GetEndpointAddressesForService(serviceName string, namespace string, portName string) []v1.EndpointAddress {
	var allAddresses []v1.EndpointAddress

	w.RLock()
	defer w.RUnlock()

	for _, ep := range w.AllEndpoints {
		// ensure the service name matches the endpoint name
		if !strings.EqualFold(ep.Name, serviceName) {
			continue
		}
		// ensure the service name matches the endpoint name
		if !strings.EqualFold(ep.Namespace, namespace) {
			continue
		}

		for _, subset := range ep.Subsets {

			// ensure this subset contains the port we care about
			var foundRelevantPort bool
			for _, p := range subset.Ports {
				if p.Name == portName {
					foundRelevantPort = true
					break
				}
			}
			if foundRelevantPort {
				// pick all the addresses for this subset for our results
				allAddresses = append(allAddresses, subset.Addresses...)
			}
		}
	}
	return allAddresses
}

// GetEndpointAddressesForNode fetches all the subset addresses known by the watcher
// for a specific node.
func (w *Watcher) GetEndpointAddressesForNode(nodeName string) []v1.EndpointAddress {
	w.RLock()
	defer w.RUnlock()

	var allAddresses []v1.EndpointAddress
	for _, ep := range w.AllEndpoints {
		for _, subset := range ep.Subsets {
			for _, address := range subset.Addresses {
				if address.NodeName == nil {
					continue
				}
				if *address.NodeName == nodeName {
					allAddresses = append(allAddresses, address)
				}
			}
		}
	}
	return allAddresses
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

					// log.Debugln("watcher: publishChan got a config to publish but batched it")
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
	log.Debugln("watcher: publishing new cluster config with", len(cc.Config), "IPv4 addresses and", len(cc.Config6), "IPv6 addresses")
	w.ClusterConfig = cc

	// generate a new full config record
	b, _ := json.Marshal(w.ClusterConfig)
	sha := sha1.Sum(b)
	w.metrics.ClusterConfigInfo(base64.StdEncoding.EncodeToString(sha[:]), string(b))
}

func (w *Watcher) publishNodes(nodes []*v1.Node) {
	// startTime := time.Now()
	// log.Debugln("watcher: publishNodes running")
	// defer log.Debugln("watcher: publishNodes completed in", time.Since(startTime))

	// set the published nodes on the watcher
	log.Infoln("watcher: set new node config with", len(nodes), "nodes")
	w.Nodes = nodes
}

// buildClusterConfig generates a new ClusterConfig object from the existing configmap
func (w *Watcher) buildClusterConfig() (*types.ClusterConfig, error) {

	// log.Debugln("watcher: running buildClusterconfig() against configmap with", len(w.configMap.Data), "data entries")

	// newConfig represents what is coming directly from the 'green' key in the k8s configmap
	newConfig, err := w.extractConfigKey(w.ConfigMap)
	if err != nil {
		return nil, err
	}

	// if the raw config is blank, just ignore it and throw a warning
	if newConfig == nil {
		log.Warningln("watcher: w.buildClusterConfig() generated a nil rawConfig")
		return nil, nil
	}
	log.Debugln("watcher: buildClusterConfig newConfig has", len(newConfig.Config), "ipv4 configurations after extractConfigKey")

	// Update the config to eliminate any services that do not exist
	err = w.filterConfig(newConfig)
	if err != nil {
		log.Debugln("watcher: buildClusterconfig found an error when calling w.filterConfig:", err)
		return nil, err
	}
	log.Debugln("watcher: buildClusterConfig newConfig has", len(newConfig.Config), "ipv4 configurations after w.filterConfig")

	// Update the config to add the default listeners to all of the vips in the bip pool.
	if err := w.addUnicornListenersToConfig(newConfig); err != nil {
		return nil, err
	}
	log.Debugln("watcher: buildClusterConfig newConfig has", len(newConfig.Config), "ipv4 configurations after w.addListenersToConfig")

	// log.Debugln("watcher: buildClusterConfig: created a new config with", len(configuredServices), "services")

	return newConfig, nil
}

// HasConfigChanged determines if the cluster configuration has actually changed
func (w *Watcher) HasConfigChanged(currentConfig *types.ClusterConfig, newConfig *types.ClusterConfig) bool {

	// if both configs are nil, we consider them as unchanged
	if currentConfig == nil && newConfig == nil {
		log.Warningln("watcher: currentConfig and newConfig were both nil")
		return false
	}

	// if either configs have a nil (but not both), we decide things have changed every time
	if currentConfig == nil {
		log.Warningln("watcher: currentConfig was nil, so config has changed")
		return true
	}
	if newConfig == nil {
		log.Warningln("watcher: newConfig was nil, so it was ignored")
		return false
	}

	// if the new config is a nil, then we indicate nothing has changed
	// in an assumption that something is wrong or not yet populated
	if newConfig.Config == nil {
		log.Warningln("watcher: Config property was empty on new or current config")
		return false
	}

	// first, check if reflect.DeepEqual determines they are the same. If
	// DeepEqual says they haven't changed, then they havent.  If DeepEqual
	// says they have changed, then it might just be detecting a difference
	// in the order of values, so we need to look further.  As of v2.5.6,
	// this was _always_ returning that the config changed, even if you
	// can confirm they haven't with a manual diff of the JSON version of
	// both configs.
	if reflect.DeepEqual(currentConfig, newConfig) {
		// log.Infoln("watcher: deep equal matches - no values changed")
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
		w.AllServices[identity] = service

	case "DELETED":
		log.Debugln("watcher: service deleted:", service.Name)
		// w.logger.Debugf("processService - DELETED")
		delete(w.AllServices, identity)

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
		log.Infoln("watcher: node list was nil, so it was initialized as a blank node slice")
		w.Nodes = []*v1.Node{}
	}

	// if a node is added, append to the array
	// if a node is modified, iterate and search the array for the node, then replace the record
	// if a node is deleted, iterate and search the array for the node, then remove the record
	switch eventType {
	case "ADDED", "MODIFIED":
		log.Infoln("watcher: node added or modified:", node.Name)
		// w.logger.Debugf("processNode - %s - %v", eventType, node)
		var foundExistingNode bool
		for i, existingNode := range w.Nodes {
			if existingNode.Name == node.Name {
				log.Debugln("watcher: updated node:", node.Name)
				w.Nodes[i] = node
				foundExistingNode = true
				break
			}
		}
		// add the new node if it was not found already
		if !foundExistingNode {
			w.Nodes = append(w.Nodes, node)
		}
	case "DELETED":
		log.Infoln("watcher: node deleted:", node.Name, "there were", len(w.Nodes), "nodes before removal")
		for i, existing := range w.Nodes {
			if existing.Name == node.Name {
				w.Nodes = append(w.Nodes[:i], w.Nodes[i+1:]...)
			}
		}
		log.Infoln("watcher: node deleted:", node.Name, "there are now", len(w.Nodes), "nodes after removal")
	}
}

func (w *Watcher) processConfigMap(eventType watch.EventType, configmap *v1.ConfigMap) {
	log.Infoln("watcher: detected new or modified configmap:", configmap.Namespace, configmap.Name)

	if eventType == "ERROR" {
		log.Errorln("error: got error event while watching configmap", configmap.Name)
		return
	}

	// ensure that the configmap value is correct
	if configmap.Name != w.ConfigMapName {
		log.Warningln("watcher: processConfigMap was passed a configmap name that didn't match the watcher's configmap name", configmap.Name, "!=", w.ConfigMapName)
		return
	}

	w.ConfigMap = configmap
	log.Debugln("watcher: processConfigMap has set a new configmap on the watcher with name", configmap.Name)
}

// processEndpoint handles an event coming from a watch for kubernetes endpoints
func (w *Watcher) processEndpoint(eventType watch.EventType, endpoints *v1.Endpoints) {
	w.Lock()
	defer w.Unlock()

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
	case "ADDED", "MODIFIED":
		log.Debugln("watcher: there are now", len(endpoints.Subsets), "subsets for endpoint", identity)
		w.AllEndpoints[identity] = endpoints
	case "DELETED":
		log.Debugln("watcher: endpoints and all subsets deleted:", endpoints.Name)
		// w.logger.Debugf("processEndpoint - DELETED")
		delete(w.AllEndpoints, identity)

	default:
		log.Warningln("Got an unknown endpoint eventType of:", eventType)
	}

}

func (w *Watcher) extractConfigKey(configmap *v1.ConfigMap) (*types.ClusterConfig, error) {
	w.RLock()
	defer w.RUnlock()
	// Unmarshal the config map, retrieving only the configuration matching the configKey
	clusterConfig, err := types.NewClusterConfig(configmap, w.ConfigKey)
	if err != nil {
		return nil, fmt.Errorf("watcher: failed to call types.NewClusterConfig from configmap %s and config key %s with error: %w", configmap.Name, w.ConfigKey, err)
	}
	if clusterConfig.Config == nil {
		return nil, fmt.Errorf("watcher: clusterConfig.Config from types.NewClusterconfig config is nil, but error was not set")
	}
	if clusterConfig.Config6 == nil {
		return nil, fmt.Errorf("watcher: clusterConfig.Config6 from types.NewClusterconfig config is nil, but error was not set")
	}
	return clusterConfig, nil
}

// addUnicornListenersToConfig mutates the input types.ClusterConfig to add the autoSvc and autoPort
// from the watcher primary configuration, if that value is set.
func (w *Watcher) addUnicornListenersToConfig(inCC *types.ClusterConfig) error {

	// log.Debugln("unicorns: addListenersToConfig")

	// bail out if there's nothing to do.
	if w.AutoSvc == "" {
		log.Debugln("unicorns: not adding unicorns listner because the autoSvc is blank")
		return nil
	}

	// Iterate over the VIPPool and check whether Config contains a record for each of the vips.
	// If it does, check whether there's a record for w.autoPort. If so, skip. If not, create.
	// If not, create.
	autoSvc, err := types.NewServiceDef(w.AutoSvc)
	if err != nil {
		return fmt.Errorf("unicorns: unable to add listener to config. %v", err)
	}
	autoSvc.IPVSOptions.RawForwardingMethod = "i"

	for _, vip := range inCC.VIPPool {
		sVip := types.ServiceIP(vip)
		sPort := strconv.Itoa(w.AutoPort)

		// if the vip is not configured, configure it with unicorns
		if _, ok := inCC.Config[sVip]; !ok {
			// Create a new portmap
			// log.Debugln("unicorns: adding unicorns service IP:", sVip, autoSvc)
			inCC.Config[sVip] = types.PortMap{
				sPort: autoSvc,
			}

			// if the vip is configured,but the service port is not configured, configure it with unicorns
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

// GetPortNumberForService returns the port number for the service behind a VIP.
func (w *Watcher) GetPortNumberForService(namespace string, serviceName string, portName string) int32 {
	w.RLock()
	defer w.RUnlock()

	for _, ep := range w.AllEndpoints {
		if ep.Name != serviceName {
			continue
		}
		if ep.Namespace != namespace {
			continue
		}
		for _, subset := range ep.Subsets {
			for _, port := range subset.Ports {
				if port.Name == portName {
					return port.Port
				}
			}
		}
	}
	return 0
}

// serviceHasValidEndpoints filters out any service that does not have
// an endpoint in its endpoints list. Kubernetes will remove these services
// from the kube-proxy, and we should, too.
func (w *Watcher) ServiceHasValidEndpoints(ns, svc string) bool {
	service := fmt.Sprintf("%s/%s", ns, svc)

	// if w.AllEndpoints[service] == nil {
	// 	log.Debugln("watcher: skipped nil endpoints list for service", service)
	// }

	if ep, ok := w.AllEndpoints[service]; ok {
		for _, subset := range ep.Subsets {
			if len(subset.Addresses) != 0 {
				return true
			}
		}
	}

	return false
}

func (w *Watcher) userServiceInEndpoints(ns, svc, portName string) bool {

	w.RLock()
	defer w.RUnlock()

	service := fmt.Sprintf("%s/%s", ns, svc)
	ep, ok := w.AllEndpoints[service]
	// log.Debugln("watcher: userServiceInEndpoints: service", ok, service, ep)

	if ok {
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

func (w *Watcher) ServiceExistsInConfig(config *types.ClusterConfig, serviceName string, namespace string, portName string) bool {
	w.RLock()
	defer w.RUnlock()

	for _, portMap := range config.Config {
		for _, port := range portMap {
			if port.Namespace == namespace {
				if port.PortName == portName {
					if port.Service == serviceName {
						return true
					}
				}
			}
		}
	}

	return false
}

// serviceClusterIPIsSet returns a boolean value indicating whether the
// clusterIP value is set in the target service. If not, we do not configure
// the service.
func (w *Watcher) serviceClusterIPIsSet(ns, svc string) bool {
	w.RLock()
	defer w.RUnlock()

	service := fmt.Sprintf("%s/%s", ns, svc)

	if s, ok := w.AllServices[service]; ok {
		if s.Spec.ClusterIP == "None" || s.Spec.ClusterIP == "" {
			return false
		}
	}
	return true
}

// filterConfig filters out any service from the clusterconfig that is not present in the retrieved services.
// This ensures that we do not attempt to create a load balancer that points to a service that does not yet exist.
// Note that even though iptables has a secondary filter to remove service references that are not present in
// the kube-services chain, this is necessary in order to ensure that the load balancer does not hold a lock
// on a chain that should be deleted, which would result in kube-proxy's update failing.
func (w *Watcher) filterConfig(inCC *types.ClusterConfig) error {

	// dont filter if we get passed a nil config
	if inCC == nil {
		return fmt.Errorf("watcher: filterConfig can't run because the passed in cluster config was nil")
	}

	// track how many ports are removed for filtering reasons
	// var filteredPorts []string
	var filteredCount int

	// var notFilteredPorts []string
	if inCC.Config == nil {
		return fmt.Errorf("watcher: filterConfig can't run because the passed in cluster config was nil")
	}

	// walk the input configmap and check for matches.
	// if no match is found, continue. if a match is found, add the entire portMap back into the config
	for lbVIP, portMap := range inCC.Config {
		for port, lbTarget := range portMap {

			// if the lbTarget is nil, then there is nothing to filter
			if lbTarget == nil {
				continue
			}

			// ensure this service and target port is in the endpoints list
			if !w.userServiceInEndpoints(lbTarget.Namespace, lbTarget.Service, lbTarget.PortName) {
				// if the service doesn't exist in kube's records, we don't create it
				// filteredPorts = append(filteredPorts, lbTarget.Namespace+"/"+lbTarget.Service+":"+port)

				// remove this item from the config because there are no endpoints for it yet
				w.Lock()
				delete(inCC.Config[lbVIP], port)
				w.Unlock()

				filteredCount++
				continue
			}

			if !w.serviceClusterIPIsSet(lbTarget.Namespace, lbTarget.Service) {
				// filteredPorts = append(filteredPorts, lbTarget.Namespace+"/"+lbTarget.Service+":"+port)

				// remove this item from the config because there isn't a clusterIP set for it yet
				w.Lock()
				delete(inCC.Config[lbVIP], port)
				w.Unlock()

				filteredCount++
				continue
			}

			if !w.ServiceHasValidEndpoints(lbTarget.Namespace, lbTarget.Service) {
				// w.logger.Debugf("filtering service with no Endpoints - %s", match)
				// log.Warningln("service has no endpoints:", lbTarget.Namespace, lbTarget.Service)
				// filteredPorts = append(filteredPorts, lbTarget.Namespace+"/"+lbTarget.Service+":"+port)

				// delete service if it does not have valid endpoints
				w.Lock()
				delete(inCC.Config[lbVIP], port)
				w.Unlock()

				filteredCount++
				continue
			}

			// notFilteredPorts = append(notFilteredPorts, lbTarget.Namespace+"/"+lbTarget.Service+":"+lbTarget.PortName)
		}
	}

	// display how many ports were filtered and what they were
	// log.Debugln("watcher: filterConfig filtered", filteredCount, "services out of the cluster config:", strings.Join(filteredPorts, ", "))
	log.Debugln("watcher: filterConfig filtered", filteredCount, "services out of the cluster config")
	if inCC.Config == nil {
		log.Debugln("watcher: filterConfig inCC.Config == nil")
		return fmt.Errorf("watcher: inCC.Config nil after filtering services")
	}

	// debug output how many services _are_ configured
	// log.Debugln("watcher: after filtering there were", len(notFilteredPorts), "services in the cluster config:", strings.Join(notFilteredPorts, ","))

	return nil
}

// func (n *Node) HasServiceRunning(namespace, service, portName string) bool {
// 	for _, endpoint := range n.Endpoints {
// 		if endpoint.Namespace == namespace && endpoint.Service == service {
// 			for _, subset := range endpoint.Subsets {
// 				if len(subset.Addresses) == 0 {
// 					return false
// 				}

// 				for _, port := range subset.Ports {
// 					if port.Name == portName {
// 						return true
// 					}
// 				}
// 			}
// 		}
// 	}
// 	return false
// }

// NodeHasServiceRunning checks if the node has any endpoints (pods) running for a given service
func (w *Watcher) NodeHasServiceRunning(nodeName string, namespace string, service string, portName string) bool {
	// podIPs := w.GetPodIPsOnNode(nodeName, service, namespace, portName)
	nodePodIPs := w.GetPodIPsOnNode(nodeName, service, namespace, portName)
	return len(nodePodIPs) > 0
	// endpointAddresses := w.GetEndpointAddressesForService(service, namespace, portName)
	// return len(endpointAddresses) > 0
}

// func (n *Node) HasServiceRunning(namespace, service, portName string) bool {
// 	for _, endpoint := range n.Endpoints {
// 		if endpoint.Namespace == namespace && endpoint.Service == service {
// 			for _, subset := range endpoint.Subsets {
// 				if len(subset.Addresses) == 0 {
// 					return false
// 				}

// 				for _, port := range subset.Ports {
// 					if port.Name == portName {
// 						return true
// 					}
// 				}
// 			}
// 		}
// 	}
// 	return false
// }
