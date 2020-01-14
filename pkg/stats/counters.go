package stats

import (
	"sync/atomic"

	"github.com/clarkduvall/hyperloglog"
	"github.com/google/gopacket"
)

type hash uint64

func (h hash) Sum64() uint64 { return uint64(h) }

// Various counters
// rdei-lb.tcp.flows            -   gauge of active connections as measured by the total # of unique src,dst tuples / 2
// rdei-lb.tcp.tx               -   gauge of transmit bytes
// rdei-lb.tcp.rx               -   gauge of receive bytes
// rdei-lb.tcp.syn-ack          -   gauge of established sessions. this is the number of new connections established during the window.
// rdei-lb.tcp.rst              -   gauge of reset indicators. large swings in this value sustained across many vips is indicative of problems with the network, while anomolies isolated to a single address point to application issues
// rdei-lb.tcp.fin              -   gauge of closed sessions.
// rdei-lb.udp.flows            -   gauge of active connections as measure by the total # of unique src,dst tuples.
// rdei-lb.udp.tx               -   gauge of transmit bytes
// rdei-lb.udp.rx               -   gauge of receive bytes
type counters struct {
	IsTCP     bool
	Namespace string
	Service   string
	PortName  string
	TCP       tcpCounters
	UDP       udpCounters
}

type tcpCounters struct {
	flows  *hyperloglog.HyperLogLogPlus
	SYNACK uint64
	RST    uint64
	FIN    uint64
	Tx     uint64
	Rx     uint64
}
type udpCounters struct {
	flows *hyperloglog.HyperLogLogPlus
	Tx    uint64
	Rx    uint64
}

// NewCounters returns an initialized counters object.
// A HyperLogLog++ will be intantiated as a part of this in order to keep track
// of the unique number of flows observed in the window period. Where this is a
// challenge is with respect to measuring bidirectional flows. In the case of
// TCP, you can simply divide the HLL cardinality count by two, because all flows
// are by definition bidirectional. For UDP, there doesn't seem to be a good way
// to track the total number of bidirectional flows. But outbound flows from the VIP
// address are actually not possible, so it only makes sense to track inbound flows.
func NewCounters(ns, svc, p string, isTCP bool) *counters {
	tHLL, _ := hyperloglog.NewPlus(18)
	uHLL, _ := hyperloglog.NewPlus(18)
	return &counters{
		Namespace: ns,
		Service:   svc,
		PortName:  p,
		IsTCP:     isTCP,
		TCP: tcpCounters{
			flows: tHLL,
		},
		UDP: udpCounters{
			flows: uHLL,
		},
	}
}

// TCP Functions
func (c *counters) AddTCPRx(b uint64) { atomic.AddUint64(&c.TCP.Rx, b) }
func (c *counters) AddTCPTx(b uint64) { atomic.AddUint64(&c.TCP.Tx, b) }
func (c *counters) IncrTCPSynAck()    { atomic.AddUint64(&c.TCP.SYNACK, 1) }
func (c *counters) IncrTCPFin()       { atomic.AddUint64(&c.TCP.FIN, 1) }
func (c *counters) IncrTCPRst()       { atomic.AddUint64(&c.TCP.RST, 1) }
func (c *counters) AddTCPFlow(f gopacket.Flow) {
	h := hash(f.FastHash())
	c.TCP.flows.Add(h)
}

// UDP Functions
func (c *counters) AddUDPRx(b uint64) { atomic.AddUint64(&c.UDP.Rx, b) }
func (c *counters) AddUDPTx(b uint64) { atomic.AddUint64(&c.UDP.Tx, b) }
func (c *counters) AddUDPFlow(f gopacket.Flow) {
	h := hash(f.FastHash())
	c.UDP.flows.Add(h)
}

// Getters *reset the value* of the counter that they retrieve. All of the counters
// that we retrieve as apart of this type are window counters, meaning they are
// keeping track of all of the data from the beginning of time
// These counters reset because the actual running tally of values is kept outside of
// this context. Think of them in terms of "increment-by-n" rather than as absolute
// counters of events

// TCP Getters
func (c *counters) GetTCPRx() uint64     { return atomic.SwapUint64(&c.TCP.Rx, 0) }
func (c *counters) GetTCPTx() uint64     { return atomic.SwapUint64(&c.TCP.Tx, 0) }
func (c *counters) GetTCPSynAck() uint64 { return atomic.SwapUint64(&c.TCP.SYNACK, 0) }
func (c *counters) GetTCPFin() uint64    { return atomic.SwapUint64(&c.TCP.FIN, 0) }
func (c *counters) GetTCPRst() uint64    { return atomic.SwapUint64(&c.TCP.RST, 0) }
func (c *counters) GetTCPFlowCount() uint64 {
	n := c.TCP.flows.Count()
	c.TCP.flows.Clear()
	return n / 2
}

// UDP Getters
func (c *counters) GetUDPRx() uint64 { return atomic.SwapUint64(&c.UDP.Rx, 0) }
func (c *counters) GetUDPTx() uint64 { return atomic.SwapUint64(&c.UDP.Tx, 0) }
func (c *counters) GetUDPFlowCount() uint64 {
	n := c.UDP.flows.Count()
	c.UDP.flows.Clear()
	return n
}
