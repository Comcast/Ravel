package iptables

import (
	"strconv"
	"time"

	"github.com/Comcast/Ravel/pkg/stats"
	"github.com/prometheus/client_golang/prometheus"
)

type iptablesMetrics interface {
	IPTables(operation string, tries int, err error, d time.Duration)

	ChainRemoved(name, rule string)
	ChainGauge(len int, kind string)
}

type metrics struct {
	lbKind    string
	configKey string

	iptablesCount   *prometheus.CounterVec
	iptablesLatency *prometheus.HistogramVec

	chainRemoved *prometheus.CounterVec
	chainGauge   *prometheus.GaugeVec
}

func (m *metrics) IPTables(operation string, tries int, err error, d time.Duration) {
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	labels := prometheus.Labels{"lb": m.lbKind,
		"seczone":   m.configKey,
		"operation": operation,
		"attempts":  strconv.Itoa(tries),
		"outcome":   outcome}
	m.iptablesCount.With(labels).Add(1)
	m.iptablesLatency.With(labels).Observe(float64(d.Nanoseconds() / 1000))
}

func (m *metrics) ChainRemoved(name, rule string) {
	// If the cardinality of this metric becomes a problem in production,
	// refer to the reset lifecycle in pkg/system/watcherMetrics.go for
	// an example of one approach to resetting the metric and removing
	// stale values.
	m.chainRemoved.With(prometheus.Labels{"lb": m.lbKind,
		"seczone": m.configKey,
		"name":    name,
		"rule":    rule}).Add(1)
}

func (m *metrics) ChainGauge(l int, kind string) {
	m.chainGauge.With(prometheus.Labels{"lb": m.lbKind,
		"seczone": m.configKey,
		"kind":    kind,
	}).Set(float64(l))
}

func NewMetrics(lbKind, configKey string) *metrics {

	defaultLabels := []string{"lb", "seczone"}
	iptablesLabels := append(defaultLabels, []string{"operation", "attempts", "outcome"}...)
	chainInfoLabels := append(defaultLabels, []string{"name", "rule"}...)
	chainGaugeLabels := append(defaultLabels, []string{"kind"}...)

	// counter iptables_operation_count
	iptablesCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: stats.Prefix + "iptables_operation_count",
		Help: "is a count of operations performed against iptables and the status",
	}, iptablesLabels)

	// histogram iptables_latency
	iptablesLatency := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    stats.Prefix + "iptables_latency_microseconds",
		Help:    "is a histogram denoting the amount of time it takes to perform various iptables operations. labels for operation save|restore|flush and for outcome error|success",
		Buckets: stats.LatencyBuckets,
	}, iptablesLabels)

	// counter iptables_chain_removal_count
	chainRemoved := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: stats.Prefix + "iptables_chain_removal_count",
		Help: "is a count of all of the chain/rules that have been removed from iptables. this indicates that the client has incorrectly configured their backing service",
	}, chainInfoLabels)

	// guage iptables_chain_size
	chainGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: stats.Prefix + "iptables_chain_size",
		Help: "is twi guages, one for the inbound/calculated chain size, and one for the configured size.",
	}, chainGaugeLabels)

	prometheus.MustRegister(iptablesCount)
	prometheus.MustRegister(iptablesLatency)
	prometheus.MustRegister(chainRemoved)
	prometheus.MustRegister(chainGauge)

	return &metrics{
		lbKind:    lbKind,
		configKey: configKey,

		iptablesCount:   iptablesCount,
		iptablesLatency: iptablesLatency,

		chainRemoved: chainRemoved,
		chainGauge:   chainGauge,
	}
}
