package stats

import "github.com/prometheus/client_golang/prometheus"

type LBKind string

const KindBGP = "bgp"
const KindDirector = "director"
const KindRealServer = "realserver"
const Prefix = "rdei_lb_"

// consts for prometheus initialization
var (
	metricTcpState = Prefix + "tcp_state_count"
	helpTcpState   = "A counter variable that measures protocol, port name, namespace, service, state events like rst or synack, and counts for respective event types"

	metricFlows = Prefix + "flows_count"
	helpFlows   = "a counter to measure the increase in active tcp and udp connections"

	metricTx = Prefix + "tx_bytes"
	helpTx   = "a counter to measure the bytes transmitted"
	metricRx = Prefix + "rx_bytes"
	helpRx   = "a counter to measure the bytes received"

	// state events. these are not metrics, they're labels within a metric
	stateSynAck = "syn_ack"
	stateFin    = "fin"
	stateRst    = "rst"

	LatencyBuckets []float64 = []float64{100, 1000, 10000, 50000, 100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000, 900000, 1000000, 1500000, 2000000, 3000000}
)

var standardLabels = []string{"lb", "vip", "port", "protocol", "port_name", "namespace", "service"}
var stateLabels = []string{"lb", "vip", "port", "state_event", "protocol", "port_name", "namespace", "service"}

type flowMetrics struct {
	// counters for all state events
	rxMetric    *prometheus.CounterVec
	txMetric    *prometheus.CounterVec
	stateMetric *prometheus.CounterVec
	flowsMetric *prometheus.CounterVec

	lbKind string
}

// simple instantiation of all maps
func newFlowMetrics(kind LBKind) *flowMetrics {
	return &flowMetrics{

		lbKind: string(kind),

		txMetric:    newCounter(metricTx, helpTx, standardLabels),
		rxMetric:    newCounter(metricRx, helpRx, standardLabels),
		stateMetric: newCounter(metricTcpState, helpTcpState, stateLabels),
		flowsMetric: newCounter(metricFlows, helpFlows, standardLabels),
	}
}

func (p *flowMetrics) tx(vip, port, protocol, namespace, portName, service string, value uint64) {
	p.txMetric.With(prometheus.Labels{
		"lb":        p.lbKind,
		"vip":       vip,
		"port":      port,
		"namespace": namespace,
		"service":   service,
		"port_name": portName,
		"protocol":  protocol,
	}).Add(float64(value))
}

func (p *flowMetrics) rx(vip, port, protocol, namespace, portName, service string, value uint64) {
	p.rxMetric.With(prometheus.Labels{
		"lb":        p.lbKind,
		"vip":       vip,
		"port":      port,
		"namespace": namespace,
		"service":   service,
		"port_name": portName,
		"protocol":  protocol,
	}).Add(float64(value))
}

func (p *flowMetrics) flows(vip, port, protocol, namespace, portName, service string, value uint64) {
	p.flowsMetric.With(prometheus.Labels{
		"lb":        p.lbKind,
		"vip":       vip,
		"port":      port,
		"namespace": namespace,
		"service":   service,
		"port_name": portName,
		"protocol":  protocol,
	}).Add(float64(value))
}

func (p *flowMetrics) tcpState(vip, port, stateEvent, protocol, namespace, portName, service string, value uint64) {
	p.stateMetric.With(prometheus.Labels{
		"lb":          p.lbKind,
		"vip":         vip,
		"port":        port,
		"state_event": stateEvent,
		"namespace":   namespace,
		"service":     service,
		"port_name":   portName,
		"protocol":    protocol,
	}).Add(float64(value))
}

func newCounter(name, help string, labels []string) *prometheus.CounterVec {
	newCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: name,
		Help: help,
	}, labels)
	prometheus.MustRegister(newCounter)
	return newCounter
}
