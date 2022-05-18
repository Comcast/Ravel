package watcher

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Comcast/Ravel/pkg/stats"
)

type WatcherMetrics interface {
	// WatchBackoffDuration is a guage indicating the current length
	// of the backoff duration.
	WatchBackoffDuration(d time.Duration)

	// indicates that an error on initialization has occurred
	// counter rdel_lb_kube_connect_err_count
	WatchErr(endpoint string, err error)

	// indicates that the watcher has been reinitialized
	// counter rdel_lb_watch_init_count
	// bucket rdei_lb_watch_init_microseconds
	WatchInit(d time.Duration)

	// indicates how often new data arrives through each of the watch channels
	// counter rdei_lb_watch_data_count
	WatchData(endpoint string)

	// indicator of how often the cluster config is rebuilt and re-sent to the client
	// counter rdei_lb_watch_cluster_config_count
	WatchClusterConfig(event string)

	// contains the full applied configutration and a hash of it
	ClusterConfigInfo(sha string, info string)
}

type Metrics struct {
	sync.Mutex

	kind    string
	secZone string

	backoffDuration *prometheus.GaugeVec
	errCount        *prometheus.CounterVec
	initCount       *prometheus.CounterVec
	initLatency     *prometheus.HistogramVec
	dataCount       *prometheus.CounterVec
	configCount     *prometheus.CounterVec
	configInfo      *prometheus.GaugeVec
}

func (m *Metrics) WatchBackoffDuration(d time.Duration) {
	m.backoffDuration.With(prometheus.Labels{"lb": m.kind, "seczone": m.secZone}).Set(d.Seconds())
}

func (m *Metrics) WatchErr(endpoint string, err error) {
	// adding labels initializes to 0, even if no error
	c := m.errCount.With(prometheus.Labels{"lb": m.kind, "seczone": m.secZone, "endpoint": endpoint})
	if err != nil {
		c.Add(1)
	}
}

func (m *Metrics) WatchInit(d time.Duration) {
	labels := prometheus.Labels{"lb": m.kind, "seczone": m.secZone}
	m.initCount.With(labels).Add(1)
	m.initLatency.With(labels).Observe(float64(d.Nanoseconds() / 1000))
}
func (m *Metrics) WatchData(endpoint string) {
	m.dataCount.With(prometheus.Labels{"lb": m.kind, "seczone": m.secZone, "endpoint": endpoint}).Add(1)
}
func (m *Metrics) WatchClusterConfig(event string) {
	m.configCount.With(prometheus.Labels{"lb": m.kind, "seczone": m.secZone, "event": event}).Add(1)
}
func (m *Metrics) ClusterConfigInfo(sha string, info string) {
	// because this has potential to be a high-cardinality metric,
	// clearing the metrics every few minutes. Note that this may result
	// in data loss by prometheus federation. There is no way to reset this
	// metric while also ensuring that the federation server has read
	// the most recent data. Or at least no way that I can think of.

	// TODO: remove this entirely
	// now := time.Now()
	// if m.clusterConfigInfoNextResetTime.Sub(now) < 0 {
	// 	m.Lock()
	// 	defer m.Unlock()
	// 	m.configInfo.Reset()
	// 	m.clusterConfigInfoNextResetTime = now.Add(6 * time.Minute)
	// }
	// m.configInfo.With(prometheus.Labels{"lb": m.kind,
	// 	"seczone": m.secZone,
	// 	"sha":     sha,
	// 	"info":    info,
	// 	"date":    time.Now().Format(time.RFC3339)}).Set(1)
}

// NewWatcherMetrics creates a new watcherMetrics struct
func NewWatcherMetrics(kind, secZone string) WatcherMetrics {
	defaultLabels := []string{"lb", "seczone"}
	endpointLabels := append(defaultLabels, []string{"endpoint"}...)
	eventLabels := append(defaultLabels, []string{"event"}...)
	infoLabels := append(defaultLabels, []string{"sha", "info", "date"}...)

	// counter reconfigure_count
	watchErr := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: stats.Prefix + "kube_connect_err_count",
		Help: "is a count of errors connecting to kube, broken out by labels indicating the endpoint",
	}, endpointLabels)

	// counter watch_init_count
	initCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: stats.Prefix + "watch_init_count",
		Help: "is a count of watch init events.",
	}, defaultLabels)

	// histogram watch_init_latency_microseconds
	watchLatency := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    stats.Prefix + "watch_init_latency_microseconds",
		Help:    "is a histogram denoting the amount of time it took to reestablish all of the watches",
		Buckets: stats.LatencyBuckets,
	}, defaultLabels)

	// counter watch_data_count
	dataCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: stats.Prefix + "watch_data_count",
		Help: "is a count of data inbound from the kuberntes watch events, broken out by endpoint",
	}, endpointLabels)

	// counter watch_cluster_config_count
	reconfigCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: stats.Prefix + "watch_cluster_config_count",
		Help: "is a count of how often a cluster config is regenerated, broken out by event - noop|publis|error",
	}, eventLabels)

	// gauge config_info
	configInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: stats.Prefix + "cluster_config_info",
		Help: "contains the current cluster config and a sha hash of the config",
	}, infoLabels)

	// gauge config_info
	backoffDuration := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: stats.Prefix + "watch_backoff_duration",
		Help: "returns the current value of the watch backoff duration. a non-1s duration indicates that the backoff is present and the load balancer is unable to communicate with the api server",
	}, defaultLabels)

	prometheus.MustRegister(configInfo)
	prometheus.MustRegister(reconfigCount)
	prometheus.MustRegister(dataCount)
	prometheus.MustRegister(watchLatency)
	prometheus.MustRegister(initCount)
	prometheus.MustRegister(watchErr)
	prometheus.MustRegister(backoffDuration)

	backoffDuration.With(prometheus.Labels{"lb": kind, "seczone": secZone})

	return &Metrics{
		kind:    kind,
		secZone: secZone,

		backoffDuration: backoffDuration,
		configInfo:      configInfo,
		configCount:     reconfigCount,
		dataCount:       dataCount,
		initLatency:     watchLatency,
		initCount:       initCount,
		errCount:        watchErr,
	}
}
