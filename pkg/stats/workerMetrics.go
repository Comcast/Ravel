package stats

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type WorkerStateMetrics struct {
	kind    string
	secZone string

	reconfigure        *prometheus.CounterVec
	reconfigureLatency *prometheus.HistogramVec
	queueDepth         *prometheus.GaugeVec
	nodeUpdate         *prometheus.CounterVec
	configUpdate       *prometheus.CounterVec
	arpingDupIP        *prometheus.CounterVec
	arpingIFDown       *prometheus.CounterVec
	arpingFailUnknown  *prometheus.CounterVec

	// loopback addition errors
	loopbackAdditions       *prometheus.CounterVec
	loopbackAdditionErr     *prometheus.CounterVec
	loopbackRemovals        *prometheus.CounterVec
	loopbackRemovalErr      *prometheus.CounterVec
	loopbackTotalConfigured *prometheus.GaugeVec
	loopbackConfigHealthy   *prometheus.GaugeVec
	iptablesWriteFail       *prometheus.GaugeVec
}

// Reconfigure is the end-to-end reconfiguration event.
// counter reconfigure_count
// bucket reconfigure_latency
func (w *WorkerStateMetrics) Reconfigure(outcome string, d time.Duration) {
	labels := prometheus.Labels{"lb": w.kind, "seczone": w.secZone, "outcome": outcome}
	w.reconfigure.With(labels).Add(1)
	w.reconfigureLatency.With(labels).Observe(float64(d.Nanoseconds() / 1000))
}

// QueueDepth is the depth of the configuration channel
// gauge config_chan_depth
func (w *WorkerStateMetrics) QueueDepth(depth int) {
	w.queueDepth.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone}).Set(float64(depth))
}

func (w *WorkerStateMetrics) NodeUpdate(outcome string) {
	w.nodeUpdate.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone, "outcome": outcome}).Add(1)
}

func (w *WorkerStateMetrics) ConfigUpdate() {
	w.configUpdate.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone}).Add(1)
}

func (w *WorkerStateMetrics) LoopbackAdditions(additions int, addrKind string) {
	w.loopbackAdditions.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone, "addrKind": addrKind}).Add(float64(additions))
}

func (w *WorkerStateMetrics) LoopbackAdditionErr(errs int, addrKind string) {
	w.loopbackAdditionErr.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone, "addrKind": addrKind}).Add(float64(errs))
}

func (w *WorkerStateMetrics) LoopbackRemovals(removals int, addrKind string) {
	w.loopbackRemovals.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone, "addrKind": addrKind}).Add(float64(removals))
}

func (w *WorkerStateMetrics) LoopbackRemovalErr(errs int, addrKind string) {
	w.loopbackRemovalErr.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone, "addrKind": addrKind}).Add(float64(errs))
}

func (w *WorkerStateMetrics) LoopbackTotalDesired(totals int, addrKind string) {
	w.loopbackTotalConfigured.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone, "addrKind": addrKind}).Set(float64(totals))
}

func (w *WorkerStateMetrics) LoopbackConfigHealthy(up int, addrKind string) {
	w.loopbackConfigHealthy.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone, "addrKind": addrKind}).Set(float64(up))
}

func (w *WorkerStateMetrics) IptablesWriteFailure(status int) {
	w.iptablesWriteFail.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone, "addrKind": ""}).Set(float64(status))
}

// ArpingFailure switch on what type of metric we should increment
func (w *WorkerStateMetrics) ArpingFailure(err error) {
	switch {
	case strings.Contains(err.Error(), "exit status 1"):
		w.arpingDupIPFail()
	case strings.Contains(err.Error(), "exit status 2"):
		w.arpingIFFail()
	default:
		w.arpingUnknownFail()
	}
}

// arpingDupIP is a duplicate IP fail of arping
// counter arping_dup_ip
func (w *WorkerStateMetrics) arpingDupIPFail() {
	w.arpingDupIP.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone}).Add(float64(1))
}

// arpingIFFail is a device down fail for arp
// counter arping_if_down
func (w *WorkerStateMetrics) arpingIFFail() {
	w.arpingIFDown.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone}).Add(float64(1))
}

// arpingIFFail is a device down fail for arp
// counter arping_if_down
func (w *WorkerStateMetrics) arpingUnknownFail() {
	w.arpingFailUnknown.With(prometheus.Labels{"lb": w.kind, "seczone": w.secZone}).Add(float64(1))
}

func NewWorkerStateMetrics(kind, secZone string) *WorkerStateMetrics {

	defaultLabels := []string{"lb", "seczone"}
	lvsLabels := []string{"lb", "seczone", "addrKind"}
	reconfigLabels := append(defaultLabels, []string{"outcome"}...)

	// counter reconfigure_count
	reconfig_count := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Prefix + "reconfigure_count",
		Help: "is a count of reconfiguration events with labels denoting a success|error|noop",
	}, reconfigLabels)

	// histogram reconfigure_bucket
	reconfig_bucket := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    Prefix + "reconfigure_latency_microseconds",
		Help:    "is a histogram denoting the amount of time an end-to-end reconfiguration took, split out by labels on the outcome.",
		Buckets: LatencyBuckets,
	}, reconfigLabels)

	// gauge channel_depth
	channel_depth := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: Prefix + "channel_depth",
		Help: "is a gauge denoting the number of inbound clusterconfig objects in the configchan. a value greater than 1 indicates a potential slowdown or deadlock",
	}, defaultLabels)

	// counter node_update_count
	node_update_count := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Prefix + "node_update_count",
		Help: "is a count of updates to the node or nodes array that are determined to be different from the current stored value",
	}, reconfigLabels)

	// counter node_update_count
	config_update_count := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Prefix + "config_update_count",
		Help: "is a count of clusterConfig updates received by the worker",
	}, defaultLabels)

	// arping duplicate IP
	arping_dup_ip := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Prefix + "arping_duplicate_ip",
		Help: "is a counter indicating the amount of times the linux arping command exits with exit status 1 indicating that a duplicate IP is found in the ARP cache. This has been tied to vaquero misconfigurations that result in failed MLAG bond interfaces",
	}, defaultLabels)

	// arping ethernet interface down
	arping_if_down := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Prefix + "arping_if_down",
		Help: "is a counter indicating the amount of times the linux arping command exits with exit status 2 indicating that the target ethernet device is down",
	}, defaultLabels)

	// arping ethernet interface down
	arping_unknown := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Prefix + "arping_fail_unknown",
		Help: "is a counter indicating the amount of times the linux arping command exits with unknown status",
	}, defaultLabels)

	// addition of address to loopback
	loopback_addition := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Prefix + "loopback_addition",
		Help: "is a counter indicating the amount of times an address was added to the loopback address by the BGP worker",
	}, lvsLabels)

	// loopback addition err
	loopback_addition_err := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Prefix + "loopback_addition_err",
		Help: "is a counter indicating the amount of times an error was seen adding an address to the loopback address by the BGP worker",
	}, lvsLabels)

	// removal of address from loopback
	loopback_removal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Prefix + "loopback_removal",
		Help: "is a counter indicating the amount of times an address was removed from the loopback address by the BGP worker",
	}, lvsLabels)

	// loopback removal err
	loopback_removal_err := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Prefix + "loopback_removal_err",
		Help: "is a counter indicating the amount of times an error was seen removing an address to the loopback address by the BGP worker",
	}, lvsLabels)

	// addition of address to loopback
	loopback_total_configured := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: Prefix + "loopback_total_configured",
		Help: "is a counter indicating the total quantity of addresses are added to the loopback interface by the BGP worker",
	}, lvsLabels)

	// addition of address to loopback
	loopback_configuration_healthy := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: Prefix + "loopback_configuration_healthy",
		Help: "is a counter indicator that there are no errors in loopback if configuration",
	}, lvsLabels)

	// failure to write to iptables
	iptables_write_failure := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: Prefix + "iptables_write_failure",
		Help: "is a gauge indicating if we failed to write to iptables",
	}, lvsLabels)

	prometheus.MustRegister(reconfig_count)
	prometheus.MustRegister(channel_depth)
	prometheus.MustRegister(reconfig_bucket)
	prometheus.MustRegister(node_update_count)
	prometheus.MustRegister(config_update_count)
	prometheus.MustRegister(arping_dup_ip)
	prometheus.MustRegister(arping_if_down)
	prometheus.MustRegister(arping_unknown)
	prometheus.MustRegister(loopback_addition)
	prometheus.MustRegister(loopback_addition_err)
	prometheus.MustRegister(loopback_removal)
	prometheus.MustRegister(loopback_removal_err)
	prometheus.MustRegister(loopback_total_configured)
	prometheus.MustRegister(loopback_configuration_healthy)
	prometheus.MustRegister(iptables_write_failure)

	// init error counters to 0
	arping_dup_ip.With(prometheus.Labels{"lb": kind, "seczone": secZone})
	arping_if_down.With(prometheus.Labels{"lb": kind, "seczone": secZone})
	arping_unknown.With(prometheus.Labels{"lb": kind, "seczone": secZone})

	return &WorkerStateMetrics{
		kind:    kind,
		secZone: secZone,

		reconfigure:             reconfig_count,
		reconfigureLatency:      reconfig_bucket,
		queueDepth:              channel_depth,
		nodeUpdate:              node_update_count,
		configUpdate:            config_update_count,
		arpingDupIP:             arping_dup_ip,
		arpingIFDown:            arping_if_down,
		arpingFailUnknown:       arping_unknown,
		loopbackAdditions:       loopback_addition,
		loopbackAdditionErr:     loopback_addition_err,
		loopbackRemovals:        loopback_removal,
		loopbackRemovalErr:      loopback_removal_err,
		loopbackTotalConfigured: loopback_total_configured,
		loopbackConfigHealthy:   loopback_configuration_healthy,
		iptablesWriteFail:       iptables_write_failure,
	}
}
