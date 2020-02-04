package stats

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/comcast/ravel/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Statistics collection for BGP load balancers. This would work for any load balancer VIP, really.

// Once a Stats is started it doesn't stop.
// 1. we need a way to receive the set of expected vip,port tuples
// 2. we need a way to periodically emit statistics about these tuples

type Stats struct {
	sync.Mutex
	// map of IP address to port to counters.
	counters map[gopacket.Endpoint]map[gopacket.Endpoint]*counters

	target   string // statsd service address
	freq     float64
	interval *time.Ticker // how often to send statistics

	device string // eth device to read packets from. (probably lo)
	kind   LBKind // bgp, ipvs

	configChan chan *types.ClusterConfig

	pcap *pcap.Handle

	prometheusPort     string
	flowMetrics        *flowMetrics
	flowMetricsEnabled bool

	ctx    context.Context
	logger logrus.FieldLogger
}

// Public Interface
// ================================================================================

func (s *Stats) EnableBPFStats() error {

	// The 1600 will have to change if we go to Jumbo Frames or something.
	if handle, err := pcap.OpenLive(s.device, 1600, false, pcap.BlockForever); err != nil {
		return fmt.Errorf("unable to instantiate pcap on device %s: %v", s.device, err)
	} else if err := handle.SetBPFFilter("tcp or udp"); err != nil {
		return fmt.Errorf("unable to set pcap filters. %v", err)
	} else {
		s.pcap = handle
	}

	go s.initMetrics()
	go s.capture()
	s.flowMetricsEnabled = true
	return nil
}

// Private Interface
// ================================================================================

// make valid prometheus label out of labels
// "-" char throws invalid metric name panic; replace with "_"
func newLabel(namespace, service, name string) string {
	join := strings.Join([]string{namespace, service, name}, "_")
	return strings.Replace(join, "-", "_", -1)
}

// captureFlowStatistics aggregates all of the data from the flow counters and transfers that data into
// the prometheus metrics values for delivery via the prometheus endpoint.
func (s *Stats) captureFlowStatistics() {
	if !s.flowMetricsEnabled {
		return
	}
	// get, and clear all of the counters.
	// TODO: this is causing a panic
	// *possible* cause: creating elements of the stats struct by-value copies the mutex;
	// writing to the map in the inner loop causes a concurrent map write causes panic
	// may have to move the writes out of the inner loop after collecting the info?
	// see https://github.com/golang/go/issues/20060
	for ip, p := range s.counters {
		for port, stats := range p {
			var protocol string
			ipStr := ip.String()
			portStr := port.String()
			if stats.IsTCP {
				tx := stats.GetTCPTx()
				rx := stats.GetTCPRx()
				sa := stats.GetTCPSynAck()
				fin := stats.GetTCPFin()
				rst := stats.GetTCPRst()
				flows := stats.GetTCPFlowCount()
				protocol = "TCP"

				s.flowMetrics.tx(ipStr, portStr, protocol, stats.Namespace, stats.PortName, stats.Service, tx)
				s.flowMetrics.rx(ipStr, portStr, protocol, stats.Namespace, stats.PortName, stats.Service, rx)
				s.flowMetrics.flows(ipStr, portStr, protocol, stats.Namespace, stats.PortName, stats.Service, flows)

				s.flowMetrics.tcpState(ipStr, portStr, stateSynAck, protocol, stats.Namespace, stats.PortName, stats.Service, sa)
				s.flowMetrics.tcpState(ipStr, portStr, stateFin, protocol, stats.Namespace, stats.PortName, stats.Service, fin)
				s.flowMetrics.tcpState(ipStr, portStr, stateRst, protocol, stats.Namespace, stats.PortName, stats.Service, rst)

				// print
				s.logger.Debugf("prometheus tcp scrape: ns=%s svc=%s port=%s addr=%v:%v prot=tcp tx=%d rx=%d synack=%d fin=%d rst=%d flows=%d",
					stats.Namespace, stats.Service, stats.PortName, ip, port, tx, rx, sa, fin, rst, flows)
			} else {
				tx := stats.GetUDPTx()
				rx := stats.GetUDPRx()
				flows := stats.GetUDPFlowCount()
				protocol = "UDP"

				s.flowMetrics.tx(ipStr, portStr, protocol, stats.Namespace, stats.PortName, stats.Service, tx)
				s.flowMetrics.rx(ipStr, portStr, protocol, stats.Namespace, stats.PortName, stats.Service, rx)
				s.flowMetrics.flows(ipStr, portStr, protocol, stats.Namespace, stats.PortName, stats.Service, flows)
			}
		}
	}
}

func NewStats(ctx context.Context, kind LBKind, device, statsHost, prometheusPort string, freq time.Duration, logger logrus.FieldLogger) (*Stats, error) {
	s := &Stats{
		kind:   kind,
		target: statsHost,
		device: device,

		configChan: make(chan *types.ClusterConfig),
		freq:       freq.Seconds(),
		interval:   time.NewTicker(freq),

		counters: map[gopacket.Endpoint]map[gopacket.Endpoint]*counters{},

		prometheusPort: prometheusPort,

		ctx:    ctx,
		logger: logger,
	}

	go s.run()
	if err := s.startServer(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Stats) UpdateConfig(c *types.ClusterConfig) error {
	s.logger.Debugf("updateconfig called")
	select {
	case s.configChan <- c:
	default:
		return fmt.Errorf("stats reconfiguration channel is full")
	}
	return nil
}

func (s *Stats) run() {
	defer s.interval.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.interval.C:
			s.captureFlowStatistics()
		case newConfig := <-s.configChan:
			s.logger.Debugf("new configuration inbound")
			s.loadConfiguration(newConfig)
		}
	}
}

// loadConfiguration takes a ClusterConfig and populates a set of
// VIP, Port tuples for use in the internal pcap capture mechanism
func (s *Stats) loadConfiguration(c *types.ClusterConfig) error {
	s.logger.Debugf("loading new configuration")
	s.Lock()
	defer s.Unlock()

	// traverse the config and generate the counters map.
	// IP addresses will be captured in ipset and the berkeley packet filter will
	// be set to filter traffic to *only* traffic on the designated VIP interfaces.
	ipset := []string{}
	for ipRaw, portMap := range c.Config {
		ip := layers.NewIPEndpoint(net.ParseIP(string(ipRaw)))

		var ip6 gopacket.Endpoint
		var has6 bool
		if ip6Raw, ok := c.IPV6[ipRaw]; ok {
			has6 = true
			ip6 = layers.NewIPEndpoint(net.ParseIP(string(ip6Raw)))
			ipset = append(ipset, string(ip6Raw))
		}

		ipset = append(ipset, string(ipRaw))

		for portRaw, cfg := range portMap {
			p, _ := strconv.Atoi(portRaw)
			tport := layers.NewTCPPortEndpoint(layers.TCPPort(p))
			uport := layers.NewUDPPortEndpoint(layers.UDPPort(p))

			if _, ok := s.counters[ip]; !ok {
				s.counters[ip] = map[gopacket.Endpoint]*counters{}
			}

			if _, ok := s.counters[ip6]; !ok && has6 {
				s.counters[ip6] = map[gopacket.Endpoint]*counters{}
			}

			if _, ok := s.counters[ip][tport]; !ok {
				s.counters[ip][tport] = NewCounters(cfg.Namespace, cfg.Service, cfg.PortName, true)
				if has6 {
					s.counters[ip6][tport] = NewCounters(cfg.Namespace, cfg.Service, cfg.PortName, true)
				}
			}
			if _, ok := s.counters[ip][uport]; !ok {
				s.counters[ip][uport] = NewCounters(cfg.Namespace, cfg.Service, cfg.PortName, false)
				if has6 {
					s.counters[ip6][uport] = NewCounters(cfg.Namespace, cfg.Service, cfg.PortName, false)
				}
			}
		}
	}

	// set the BPF filter
	s.logger.Debugf("ip set: %v", ipset)
	return s.setBPFFilter(ipset)
}

// setBPFFilter takes a list of ip addresses and sets the berkely packet filter
// in our pcap to filter traffic to just those addresses. This prevents the pcap from
// needing to process 100% of the tcp and udp traffic on a node.
func (s *Stats) setBPFFilter(ips []string) error {
	if !s.flowMetricsEnabled {
		return nil
	}
	filters := strings.Join(ips, " or ")

	return s.pcap.SetBPFFilter(fmt.Sprintf("(tcp or udp) and (%s)", filters))
}

func (s *Stats) capture() {

	// Fast parsing approach - reuse the same layers every time.
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp)
	decoded := []gopacket.LayerType{}

	for {
		var data []byte
		ci, err := s.pcap.DangerousHackReadPacketData(&data)
		// DangerousHackReadPacketData() will give data []byte the underlying buffer
		// that the C language PCAP library uses. The Go runtime won't know about that
		// memory. Since var data []byte doesn't escape this for-loop, much less func capture(),
		// it's allocated on the stack, and isn't eligible for garbage collection. I think.
		// That means the the memory that data []byte really uses isn't garbage collected either.
		// Since this function, func capture() is run by only one go routine, there shouldn't be
		// an issue with race conditions for the C PCAP library buffer.
		if err != nil {
			// shouldn't happen but we'll quit another way.
			continue
		}
		parser.DecodeLayers(data, &decoded)
		if len(decoded) != 3 {
			// icmp messages or weird ipv6 things
			continue

		} else if layers.LayerTypeTCP == decoded[2] {
			if layers.LayerTypeIPv6 == decoded[1] {
				if stats, ok := s.getCountersAndIncrement(ci.CaptureLength, ip6.SrcIP, ip6.DstIP, tcp.SrcPort, tcp.DstPort); ok {
					s.metricTCP(stats, tcp)
				}
			} else if layers.LayerTypeIPv4 == decoded[1] {
				if stats, ok := s.getCountersAndIncrement(ci.CaptureLength, ip4.SrcIP, ip4.DstIP, tcp.SrcPort, tcp.DstPort); ok {
					s.metricTCP(stats, tcp)
				}
			}

		} else if layers.LayerTypeUDP == decoded[2] {
			if layers.LayerTypeIPv6 == decoded[1] {
				if stats, ok := s.getCountersAndIncrement(ci.CaptureLength, ip6.SrcIP, ip6.DstIP, udp.SrcPort, udp.DstPort); ok {
					s.metricUDP(stats, udp)
				}
			} else if layers.LayerTypeIPv4 == decoded[1] {
				if stats, ok := s.getCountersAndIncrement(ci.CaptureLength, ip4.SrcIP, ip4.DstIP, udp.SrcPort, udp.DstPort); ok {
					s.metricUDP(stats, udp)
				}
			}
		}
	}
}

// initMetrics initialize the prometheus flowMetrics stats handlers + server
func (s *Stats) initMetrics() error {
	// initialize all the stats
	s.flowMetrics = newFlowMetrics(s.kind)
	return nil
}

func (s *Stats) startServer() error {
	s.logger.Infof("starting metrics server on: %v", s.prometheusPort)

	// we start the server async, but add a tiem delay in the code below in order to catch errors
	// quickly. this will help to prevent configuration errors where the stats port is invalid.
	errs := make(chan error)
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%s", s.prometheusPort), nil)
		if err != nil {
			s.logger.Errorf("prometheus stats server could not be initialized on port %s: %s", s.prometheusPort, err.Error())
		}
		errs <- err
	}()

	select {
	case err := <-errs:
		return fmt.Errorf("prometheus stats server could not be initialized on port %s: %s", s.prometheusPort, err.Error())
	case <-time.After(3 * time.Second):
		// break out after N seconds
	}
	return nil
}

func (s *Stats) getCountersAndIncrement(i int, srcIP, dstIP net.IP, sp, dp interface{}) (*counters, bool) {
	n := uint64(i)

	isTCP := true
	src := layers.NewIPEndpoint(srcIP)
	dst := layers.NewIPEndpoint(dstIP)
	var srcPort, dstPort gopacket.Endpoint
	switch sp.(type) {
	case layers.TCPPort:
		srcPort = layers.NewTCPPortEndpoint(sp.(layers.TCPPort))
		dstPort = layers.NewTCPPortEndpoint(dp.(layers.TCPPort))
	case layers.UDPPort:
		srcPort = layers.NewUDPPortEndpoint(sp.(layers.UDPPort))
		dstPort = layers.NewUDPPortEndpoint(dp.(layers.UDPPort))
		isTCP = false
	default:
		s.logger.Debugf("fallthrough on source port type detection.")
		return nil, false
	}

	var outStats *counters
	var found bool
	s.Lock()
	defer s.Unlock()
	if pm, ok := s.counters[dst]; ok {
		// this is receive traffic
		if stats, ok := pm[dstPort]; ok {
			found = true
			outStats = stats
			if isTCP {
				stats.AddTCPRx(n)
			} else {
				stats.AddUDPRx(n)
			}
		}

	} else if pm, ok = s.counters[src]; ok {
		// this is transmit traffic
		if stats, ok := pm[srcPort]; ok {
			found = true
			outStats = stats
			if isTCP {
				stats.AddTCPTx(n)
			} else {
				stats.AddUDPTx(n)
			}
		}
	}
	return outStats, found
}

func (s *Stats) metricUDP(stats *counters, udp layers.UDP) {
	// push the flow hash into the Counters object. This hash
	// will be added to a HyperLogLog that is used to count the
	// total number of unique flows.
	stats.AddUDPFlow(udp.TransportFlow())
}

func (s *Stats) metricTCP(stats *counters, tcp layers.TCP) {
	// push the flow hash into the Counters object. This hash
	// will be added to a HyperLogLog that is used to count the
	// total number of unique flows.
	stats.AddTCPFlow(tcp.TransportFlow())

	// count handshake, fin, resets, and congestion window messages
	// this is an if/elseif block because each of these messages is
	// believed to be mutually exclusive, i.e. the tcp implemenation
	// would not send a RST packet at the same time as a FIN packet.
	if tcp.SYN && tcp.ACK {
		stats.IncrTCPSynAck()
	} else if tcp.FIN {
		stats.IncrTCPFin()
	} else if tcp.RST {
		stats.IncrTCPRst()
	}
}

func clean(ip string) string {
	return strings.Replace(ip, ":", "_", -1)
}

// increment a counter for a TCP/UDP state event with the following labels:
/*
	stateEvent: the state event type (syn, ack, fin, tx, rx)
	protocol: are we TCP or UDP
	namespace, port name and service name of the service being load balanced
	value: the float num we are incrementing
*/
