package iptables

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/Comcast/Ravel/pkg/types"
	"github.com/Comcast/Ravel/pkg/util"
	"github.com/Comcast/Ravel/pkg/watcher"
	log "github.com/sirupsen/logrus"
)

const (
	protocolUDP = "udp"
	protocolTCP = "tcp"
)

// IPTables defines what a manager of IPTables should look like
type IPTables struct {
	chain     util.Chain
	masqChain util.Chain
	table     util.Table

	iptables *util.Runner

	masq bool

	// cli flag to exclude packets where the client ip is in this cidr range
	podCidrMasq string

	ctx     context.Context
	logger  log.FieldLogger
	metrics iptablesMetrics
}

// NewIPTables creates a new IPTables struct for managing IPTables
func NewIPTables(ctx context.Context, lbKind, configKey, podCidrMasq, chain string, masq bool, logger log.FieldLogger) (*IPTables, error) {
	return &IPTables{
		iptables: util.NewDefault(),

		chain:       util.Chain(chain),
		masqChain:   util.Chain(chain + "-MASQ"),
		table:       util.TableNAT,
		podCidrMasq: podCidrMasq,
		ctx:         ctx,
		logger:      logger,
		masq:        masq,
		metrics:     NewMetrics(lbKind, configKey),
	}, nil
}

func (i *IPTables) Flush() error {
	// Make several attempts to flush the chain.  Warn on failures.
	var err error
	idx, tries := 0, 5

	// emit a metric about the flush
	start := time.Now()
	defer func() {
		i.metrics.IPTables("flush", idx, err, time.Since(start))
	}()
	for idx < tries {
		err = i.iptables.FlushChain(i.table, i.chain)
		if err != nil && strings.Contains(err.Error(), "match by that name") {
			// if the chain does not exist, it's flushed.
			return nil
		} else if err != nil {
			// if we get an error, wait a bit then try again
			idx++
			<-time.After(111 * time.Millisecond)
			continue
		}
		return nil
	}
	return fmt.Errorf("unable to flush chain. %v", err)
}

func (i *IPTables) Save() (map[string]*RuleSet, error) {
	var err error
	var b []byte
	start := time.Now()
	defer func() {
		i.metrics.IPTables("save", 1, err, time.Since(start))
	}()

	b, err = i.iptables.Save(i.table)
	if err != nil {
		return nil, err
	}
	return i.rulesFromBytes(b)
}

func (i *IPTables) Restore(rules map[string]*RuleSet) error {
	var err error
	start := time.Now()
	defer func() {
		i.metrics.IPTables("restore", 1, err, time.Since(start))
	}()
	var b []byte
	if i.iptables.IsNFT() {
		b = BytesFromRulesClean(rules)
	} else {
		b = BytesFromRules(rules)
	}

	err = i.iptables.Restore(i.table, b, util.FlushTables, util.RestoreCounters)
	return err
}

func (i *IPTables) Merge(subset map[string]*RuleSet, wholeset map[string]*RuleSet) (map[string]*RuleSet, int, error) {
	out := map[string]*RuleSet{}

	// create a copy of the whole set, excluding the kube-ipvs chain
	for chain, set := range wholeset {
		// Remove any prefixed chains. We want to deal with them separately
		if strings.HasPrefix(chain, i.chain.String()) {
			continue
		}
		out[chain] = &RuleSet{
			ChainRule: set.ChainRule,
			Rules:     make([]string, len(set.Rules)),
		}

		for i, rule := range set.Rules {
			out[chain].Rules[i] = rule
		}

		// This is a fix for the KUBE-MARK-DROP chain in kubernetes 1.11.
		// This chain is supposed to contain a single packet marking rule, but in kube 1.11,
		// it gets filled up with duplicate rules This function deduplicates the
		// service chain.
		if chain == "KUBE-MARK-DROP" {
			kubeMarkDropSeen := map[string]bool{}
			rules := []string{}
			for _, rule := range set.Rules {
				if _, seen := kubeMarkDropSeen[rule]; seen {
					continue
				}
				rules = append(rules, rule)
			}
			out[chain].Rules = rules
		}
	}

	// update prerouting if necessary
	for _, subsetRule := range subset["PREROUTING"].Rules {
		found := false
		for _, rule := range wholeset["PREROUTING"].Rules {
			if subsetRule == rule {
				found = true
			}
		}
		if !found {
			out["PREROUTING"].Rules = append(out["PREROUTING"].Rules, subsetRule)
		}
	}

	for chainName, ruleSet := range subset {
		if chainName == "PREROUTING" {
			continue
		}
		out[chainName] = ruleSet
	}

	// metrics about the total # of rules
	all := 0
	total, match, svc, sep := chainStats("KUBE", out)
	all += total
	i.metrics.ChainGauge(match, "kube")
	i.metrics.ChainGauge(svc, "kube-services")
	i.metrics.ChainGauge(sep, "kube-endpoints")

	total, match, svc, sep = chainStats(i.chain.String(), out)
	all += total
	i.metrics.ChainGauge(match, "ravel")
	i.metrics.ChainGauge(svc, "ravel-services")
	i.metrics.ChainGauge(sep, "ravel-endpoints")
	i.metrics.ChainGauge(all, "total")

	return out, 0, nil
}

func chainStats(prefix string, subset map[string]*RuleSet) (total, match, svc, sep int) {
	for key, chain := range subset {
		ruleCount := len(chain.Rules)
		total += ruleCount
		if strings.HasPrefix(key, prefix) {
			match += ruleCount
			if strings.HasPrefix(key, prefix+"-SVC") {
				svc += ruleCount
			} else if strings.HasPrefix(key, prefix+"-SEP") {
				sep += ruleCount
			}
		}
	}
	return total, match, svc, sep
}

// GenerateRules generates a ruleset for only kube-ipvs.  a different function ought to merge these
// XXX chain rule.  This os only used by realserver package stuff seemingly.
func (i *IPTables) GenerateRules(config *types.ClusterConfig) (map[string]*RuleSet, error) {
	// output the configured servces that rules will be generated with to help with debugging
	services := []string{}
	for _, v := range config.Config {
		for _, sc := range v {
			services = append(services, sc.Namespace+"/"+sc.Service+":"+sc.PortName)
		}
	}
	log.Debugln("iptables: GenerateRules: running for", len(config.Config), "services:", strings.Join(services, ","))

	out := map[string]*RuleSet{
		"PREROUTING": {
			ChainRule: ":PREROUTING ACCEPT",
			Rules: []string{
				"-A PREROUTING -j " + i.chain.String(),
			},
		},
		i.masqChain.String(): {
			ChainRule: fmt.Sprintf(":%s - [0:0]", i.masqChain.String()),
			Rules: []string{
				i.generateMasqRule(),
			},
		},
		i.chain.String(): {
			ChainRule: ":" + i.chain.String() + " - [0:0]",
		},
	}

	// format strings for masq and jump rules
	masqFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %%s -m %%s --dport %%s -m comment --comment "%%s" -j %s`, i.chain, i.masqChain)
	jumpFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %%s -m %%s --dport %%s -m comment --comment "%%s" -j %%s`, i.chain)

	// walk the service configuration and apply all rules
	rules := []string{}
	for serviceIP, services := range config.Config {
		dest := string(serviceIP)
		for dport, service := range services {
			protocols := getServiceProtocols(service.TCPEnabled, service.UDPEnabled)
			ident := types.MakeIdent(service.Namespace, service.Service, service.PortName)
			for _, prot := range protocols {
				chain := servicePortChainName(ident, prot)
				rules = append(rules, fmt.Sprintf(masqFmt, dest, prot, prot, dport, ident))
				rules = append(rules, fmt.Sprintf(jumpFmt, dest, prot, prot, dport, ident, chain))
			}
		}
	}

	// sort and add to output
	// sort.Sort(sort.StringSlice(rules))
	out[i.chain.String()].Rules = rules

	return out, nil
}

// GenerateRulesForNodeClassic attempts to restore the original functionality of rule
// generation prior to versioned Ravel releases
func (i *IPTables) GenerateRulesForNodeClassic(w *watcher.Watcher, nodeName string, config *types.ClusterConfig, useWeightedService bool) (map[string]*RuleSet, error) {

	// Create all rules for the standard PREROUTING, RAVEL, and RAVEL-MASQ chains
	out := map[string]*RuleSet{
		"PREROUTING": {
			ChainRule: ":PREROUTING ACCEPT",
			Rules: []string{
				"-A PREROUTING -j " + i.chain.String(),
			},
		},
		i.masqChain.String(): {
			ChainRule: fmt.Sprintf(":%s - [0:0]", i.masqChain.String()),
			Rules: []string{
				i.generateMasqRule(),
			},
		},
		i.chain.String(): {
			ChainRule: ":" + i.chain.String() + " - [0:0]",
		},
	}

	// format strings for masq and jump rules
	// -A RAVEL -d 10.131.66.53/32 -p tcp -m tcp --dport 7888 -m comment --comment "altcon-sp-prod-01/fourier-proxy:proxy" -j RAVEL-SVC-BGKZXXYGCDWHIHEO
	masqFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %%s -m %%s --dport %%s -m comment --comment "%%s" -j %s`, i.chain, i.masqChain)
	weightedJumpFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %%s -m %%s --dport %%s -m comment --comment "%%s"  -m statistic --mode random --probability %%0.11f -j %%s`, i.chain)
	jumpFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %%s -m %%s --dport %%s -m comment --comment "%%s" -j %%s`, i.chain)

	// walk the service configuration and apply all rules
	// eg: this section appears to be for pods ON on this node, but NOT on other nodes?
	rules := []string{}
	for serviceIP, services := range config.Config {
		dest := string(serviceIP)
		for dport, service := range services {

			ident := types.MakeIdent(service.Namespace, service.Service, service.PortName)
			if !w.NodeHasServiceRunning(nodeName, service.Namespace, service.Service, service.PortName) {
				continue
			}

			protocols := getServiceProtocols(service.TCPEnabled, service.UDPEnabled)
			for _, prot := range protocols {
				chain := ravelServicePortChainName(ident, prot, i.chain.String())

				if i.masq {
					rules = append(rules, fmt.Sprintf(masqFmt, dest, prot, prot, dport, ident))
				}
				nodeProbability := w.GetLocalServiceWeight(nodeName, service.Namespace, service.Service, service.PortName)
				var newRule string
				if useWeightedService {
					i.logger.Debugf("probability=%v ident=%v", nodeProbability, ident)
					newRule = fmt.Sprintf(weightedJumpFmt, dest, prot, prot, dport, ident, nodeProbability, chain)
				} else {
					newRule = fmt.Sprintf(jumpFmt, dest, prot, prot, dport, ident, chain)
				}
				rules = append(rules, newRule)
			}
		}
	}

	// sort and add to output
	// sort.Sort(sort.StringSlice(rules))
	out[i.chain.String()].Rules = rules

	// Create other chains that are used to direct traffic to pods on the specified node, instead of letting
	// the traffic get taken away by rules from the CNI.
	for _, services := range config.Config {
		for _, service := range services {

			ident := types.MakeIdent(service.Namespace, service.Service, service.PortName)

			// if this node does not have a pod for this service, skip it
			if !w.NodeHasServiceRunning(nodeName, service.Namespace, service.Service, service.PortName) {
				log.Debugln("iptables: GenerateRulesForNodeClassic: skipped service because it had no instances on", nodeName, ident)
				continue
			}
			protocols := getServiceProtocols(service.TCPEnabled, service.UDPEnabled)
			// if len(protocols) == 0 {
			// 	log.Debugln("iptables: GenerateRulesForNodeClassic: service had no protocols, so TCP was assumed:", ident)
			// 	protocols = []string{"tcp"}
			// }

			var rulesAddedCount int
			for _, prot := range protocols {

				// formulate the proper iptables chain name
				chain := ravelServicePortChainName(ident, prot, i.chain.String())

				// pass if this chain is already configured
				if _, ok := out[chain]; ok {
					continue
				}

				portNumber := w.GetPortNumberForService(service.Namespace, service.Service, service.PortName)
				serviceRules := []string{}
				podIPs := w.GetPodIPsOnNode(nodeName, service.Service, service.Namespace, service.PortName)
				log.Debugln("iptables:", nodeName, service.Service, service.Namespace, service.PortName, "has", len(podIPs), "pod IPs")

				for n, ip := range podIPs {
					sepChain := ravelServiceEndpointChainName(ident, ip, prot, i.chain.String())
					probFmt := computeServiceEndpointString(chain, ident, sepChain, len(podIPs), n)

					serviceRules = append(serviceRules, probFmt)

					out[sepChain] = &RuleSet{
						ChainRule: ":" + sepChain + " - [0:0]",
						Rules: []string{
							fmt.Sprintf(`-A %s -d %s/32 -m comment --comment "%s" -j %s`, sepChain, ip, ident, i.masqChain),
							fmt.Sprintf(`-A %s -p %s -m comment --comment "%s" -m %s -j DNAT --to-destination %s:%d`, sepChain, prot, ident, prot, ip, portNumber),
						},
					}

					out[chain] = &RuleSet{
						ChainRule: fmt.Sprintf(":%s - [0:0]", chain),
						Rules:     serviceRules,
					}

					rulesAddedCount++
				}
			}
		}
	}
	log.Debugln("iptables: GenerateRulesForNode generated", len(out), "rulesets overall")
	return out, nil
}

// // GenerateRulesForNode generates rules for an individual worker node, but only for that worker node.
// func (i *IPTables) GenerateRulesForNode(w *watcher.Watcher, nodeName string, useWeightedService bool) (map[string]*RuleSet, error) {

// 	// log the services that exist for this node at the start of rule generation

// 	ruleSets := map[string]*RuleSet{
// 		"PREROUTING": {
// 			ChainRule: ":PREROUTING ACCEPT",
// 			Rules: []string{
// 				"-A PREROUTING -j " + i.chain.String(),
// 			},
// 		},
// 		i.masqChain.String(): {
// 			ChainRule: fmt.Sprintf(":%s - [0:0]", i.masqChain.String()),
// 			Rules: []string{
// 				i.generateMasqRule(),
// 			},
// 		},
// 		i.chain.String(): {
// 			ChainRule: ":" + i.chain.String() + " - [0:0]", // The string here after the : is the new chain to be created
// 		},
// 	}

// 	// format strings for masq and jump rules
// 	masqFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %%s -m %%s --dport %%s -m comment --comment "%%s" -j %s`, i.chain, i.masqChain)
// 	jumpFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %%s -m %%s --dport %%s -m comment --comment "%%s" -j %%s`, i.chain)
// 	weightedJumpFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %%s -m %%s --dport %%s -m comment --comment "%%s"  -m statistic --mode random --probability %%0.11f -j %%s`, i.chain)

// 	// walk the service configuration and apply all rules
// 	rules := []string{}
// 	for serviceIP, services := range w.ClusterConfig.Config {
// 		dest := string(serviceIP)
// 		for dport, service := range services {
// 			// if this server is not running on this node, we skip it for rule creation
// 			// if service.Service != "unicorns-blue" && service.Service != "unicorns-green" && service.Service != "unicorns-origin" {
// 			if !w.NodeHasServiceRunning(nodeName, service.Namespace, service.Service, service.PortName) {
// 				log.Debugln("iptables: GenerateRulesForNode: node", nodeName, "has NO service running for", service.Namespace+"/"+service.Service, "for port", service.PortName)
// 				continue
// 			}
// 			// }
// 			log.Debugln("iptables: GenerateRulesForNode:", nodeName, service.Namespace, service.Service, service.PortName, "has service running (A)")
// 			ident := types.MakeIdent(service.Namespace, service.Service, service.PortName)

// 			// if both protocols for a service are disabled, but the service is running
// 			// on the node (because of logic above), then just assume TCP.
// 			var protocols []string
// 			if !service.TCPEnabled && !service.UDPEnabled {
// 				protocols = []string{"tcp"}
// 			} else {
// 				protocols = getServiceProtocols(service.TCPEnabled, service.UDPEnabled)
// 			}

// 			log.Debugln("iptables: GenerateRulesForNode:", nodeName, service.Namespace, service.Service, service.PortName, "has", len(protocols), "protocols:", protocols)
// 			for _, prot := range protocols {
// 				chain := ravelServicePortChainName(ident, prot, i.chain.String())
// 				if i.masq {
// 					rules = append(rules, fmt.Sprintf(masqFmt, dest, prot, prot, dport, ident))
// 				}
// 				nodeProbability := w.GetLocalServiceWeight(nodeName, service.Namespace, service.Service, service.PortName)
// 				log.Debugln("iptables: GenerateRulesForNode: rule created for", nodeName, service.Namespace, service.Service, service.PortName, "and weight of", nodeProbability)
// 				if useWeightedService {
// 					i.logger.Debugf("probability=%v ident=%v", nodeProbability, ident)
// 					rules = append(rules, fmt.Sprintf(weightedJumpFmt, dest, prot, prot, dport, ident, nodeProbability, chain))
// 				} else {
// 					rules = append(rules, fmt.Sprintf(jumpFmt, dest, prot, prot, dport, ident, chain))
// 				}
// 			}
// 		}
// 	}

// 	// sort and add to output to ruleSet map
// 	log.Debugln("iptables: GenerateRulesForNode: phase 1 created", len(rules), "rules")
// 	sort.Strings(rules)
// 	ruleSets[i.chain.String()].Rules = rules

// 	// create the service chains for each endpoint with probability of calling endpoint emulating WRR
// 	// walk the service configuration and apply all rules
// 	for _, services := range w.ClusterConfig.Config {
// 		for _, service := range services {
// 			if service.Namespace == "egreer200" {
// 				log.Debugln("iptables: GenerateRulesForNode: egreer200 being considered in logic block B")
// 			}
// 			ident := types.MakeIdent(service.Namespace, service.Service, service.PortName)
// 			// iterate over node endpoints to see if this service is running on the node.  if its not, skip it
// 			// if service.Service != "unicorns-blue" && service.Service != "unicorns-green" && service.Service != "unicorns-origin" {
// 			// 	if !w.NodeHasServiceRunning(nodeName, service.Namespace, service.Service, service.PortName) {
// 			// 		log.Debugln("iptables: GenerateRulesForNode: service chain creation: node", nodeName, "has NO service running for", service.Namespace+"/"+service.Service, "for port", service.PortName, "as identified by ident", ident)
// 			// 		continue
// 			// 	}
// 			// }
// 			// log.Debugln("iptables: GenerateRulesForNode:", nodeName, service.Namespace, service.Service, service.PortName, "has service running (B)")

// 			// if both protocols for a service are disabled, but the service is running
// 			// on the node (because of logic above), then just assume TCP.
// 			var protocols []string
// 			if !service.TCPEnabled && !service.UDPEnabled {
// 				protocols = []string{"tcp"}
// 			} else {
// 				protocols = getServiceProtocols(service.TCPEnabled, service.UDPEnabled)
// 			}

// 			for _, prot := range protocols {

// 				chain := ravelServicePortChainName(ident, prot, i.chain.String())
// 				log.Debugln("iptables: GenerateRulesForNode: service", ident, "causing creation of iptables sevice chain:", chain)

// 				// pass if a rule is already configured - why? who knows.
// 				chainRuleset, ok := ruleSets[chain]
// 				if ok {
// 					log.Debugln("iptables: GenerateRulesForNode:", ident, "not creating chain", chain, "because it already exists in the ruleSets map:", chainRuleset)
// 					continue
// 				}

// 				portNumber := w.GetPortNumberForService(service.Namespace, service.Service, service.PortName)
// 				log.Debugln("iptables: GenerateRulesForNode: service", ident, chain, "is on port number", portNumber)

// 				podIPs := w.GetPodIPsOnNode(nodeName, service.Service, service.Namespace, service.PortName)
// 				log.Debugln("iptables: GenerateRulesForNode: getPodIPsOnNode", nodeName, service.Service, service.Namespace, service.PortName, ident, chain, "found these pod ips on this node:", podIPs)
// 				for n, ip := range podIPs {
// 					serviceRules := []string{}

// 					sepChain := ravelServiceEndpointChainName(ident, ip, prot, i.chain.String())
// 					probFmt := computeServiceEndpointString(chain, ident, sepChain, len(podIPs), n)

// 					log.Debugln("iptables: GenerateRulesForNode: ", nodeName, service.Service, service.Namespace, service.PortName, ident, chain, "service endpoint string rule:", probFmt)
// 					serviceRules = append(serviceRules, probFmt)

// 					log.Debugln("iptables: GenerateRulesForNode: adding rule set for", ident, "as chain name:", sepChain)

// 					ruleSets[sepChain] = &RuleSet{
// 						ChainRule: ":" + sepChain + " - [0:0]",
// 						Rules: []string{
// 							fmt.Sprintf(`-A %s -d %s/32 -m comment --comment "%s" -j %s`, sepChain, ip, ident, i.masqChain),
// 							fmt.Sprintf(`-A %s -p %s -m comment --comment "%s" -m %s -j DNAT --to-destination %s:%d`, sepChain, prot, ident, prot, ip, portNumber),
// 						},
// 					}
// 					ruleSets[chain] = &RuleSet{
// 						ChainRule: fmt.Sprintf(":%s - [0:0]", chain),
// 						Rules:     serviceRules,
// 					}
// 				}
// 			}
// 		}
// 	}

// 	log.Debugln("iptables: GenerateRulesForNode generated", len(ruleSets), "rulesets overall")
// 	return ruleSets, nil
// }

func (i *IPTables) BaseChain() string {
	return i.chain.String()
}

func (i *IPTables) rulesFromBytes(b []byte) (map[string]*RuleSet, error) {
	return GetSaveLines(i.table, b)
}

func (i *IPTables) generateMasqRule() string {
	if i.podCidrMasq != "" {
		return fmt.Sprintf("-A %s -j MARK ! -s %s --set-xmark 0x4000/0x4000", i.masqChain.String(), i.podCidrMasq)
	}
	return fmt.Sprintf("-A %s -j MARK --set-xmark 0x4000/0x4000", i.masqChain.String())
}

// simple fetch of protocol strings for later
// a backend can be one of, or both, but not neither protocol
func getServiceProtocols(tcp, udp bool) []string {
	protocols := []string{}
	if tcp {
		protocols = append(protocols, protocolTCP)
	}

	if udp {
		protocols = append(protocols, protocolUDP)
	}

	return protocols
}

// servicePortChainName takes the ServicePortName for a service and
// returns the associated iptables chain.  This is computed by hashing (sha256)
// then encoding to base32 and truncating with the prefix "KUBE-SVC-".  We do
// this because Iptables Chain Names must be <= 28 chars long, and the longer
// they are the harder they are to read.
// Stolen from kubernetes codebase here:
// https://github.com/kubernetes/kubernetes/blob/f2ddd60eb9e7e9e29f7a105a9a8fa020042e8e52/pkg/proxy/iptables/proxier.go#L566
func servicePortChainName(serviceStr string, protocol string) string {
	hash := sha256.Sum256([]byte(serviceStr + protocol))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return "KUBE-SVC-" + encoded[:16]
}

func ravelServicePortChainName(serviceStr string, protocol string, prefix string) string {
	hash := sha256.Sum256([]byte(serviceStr + protocol))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return prefix + "-SVC-" + encoded[:16]
}

func ravelServiceEndpointChainName(ident string, ip string, protocol string, prefix string) string {
	hash := sha256.Sum256([]byte(ident + ip + protocol))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return prefix + "-SEP-" + encoded[:16]
}

func computeEndpointProbability(i int) string {
	return fmt.Sprintf("%0.11f", 1.0/float64(i))
}

func computeServiceEndpointString(chain, ident, sepChain string, length, i int) string {
	// if last RR endpoint, return without probability as it will be 100%
	if i == length-1 {
		return fmt.Sprintf(`-A %s -m comment --comment "%s" -j %s`,
			chain,
			ident,
			sepChain)
	}
	// otherwise compute a weighted RR probability
	return fmt.Sprintf(`-A %s -m comment --comment "%s" -m statistic --mode random --probability %s -j %s`,
		chain,
		ident,
		computeEndpointProbability(length-i),
		sepChain)
}

// BytesFromRules turns a map of RuleSet pointers into a slic eof bytes
func BytesFromRules(rules map[string]*RuleSet) []byte {
	iptablesLines := []string{"*nat"}

	// Add the chain rule to the iptables rules string
	// Chain rules must be added before jumps/masqs
	for _, kubeRule := range rules {
		// Append the chain to the string
		iptablesLines = append(iptablesLines, kubeRule.ChainRule)
	}

	// Add the chain rule to the iptables rules string
	for _, kubeRule := range rules {

		iptablesLines = append(iptablesLines, kubeRule.Rules...)
	}

	// Finish with the commit at the end (newline after COMMIT required)
	iptablesLines = append(iptablesLines, "COMMIT\n")

	return []byte(strings.Join(iptablesLines, "\n"))
}

// SAME function but remove the '# comments..' or the empty '--comment'
func BytesFromRulesClean(rules map[string]*RuleSet) []byte {
	iptablesLines := []string{"*nat"}

	// Add the chain rule to the iptables rules string
	// Chain rules must be added before jumps/masqs
	line := 0
	for _, kubeRule := range rules {
		// Append the chain to the string
		iptablesLines = append(iptablesLines, kubeRule.ChainRule)
		line++
	}

	// Add the chain rule to the iptables rules string
	for _, kubeRule := range rules {
		cleanRules := []string{}
		for _, r := range kubeRule.Rules {
			line++
			ix := strings.Index(r, "--comment# ")
			if ix > 0 {
				fmt.Println("BytesFromRulesClean - removing comment:", r)
				cleanRules = append(cleanRules, r[0:ix])
				continue
			}
			ix = strings.Index(r, "# ")
			if ix > 1 {
				fmt.Println("BytesFromRulesClean - removing comment:", r)
				cleanRules = append(cleanRules, r[0:ix])
			} else {
				cleanRules = append(cleanRules, r)
			}
		}
		iptablesLines = append(iptablesLines, cleanRules...)
	}

	// Finish with the commit at the end (newline after COMMIT required)
	iptablesLines = append(iptablesLines, "COMMIT\n")

	return []byte(strings.Join(iptablesLines, "\n"))
}
