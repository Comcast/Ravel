package iptables

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/comcast/ravel/pkg/types"
	"github.com/comcast/ravel/pkg/util"
)

const (
	protocolUDP = "udp"
	protocolTCP = "tcp"
)

type IPTables interface {
	Save() (map[string]*RuleSet, error)
	Restore(map[string]*RuleSet) error
	Flush() error

	GenerateRules(config *types.ClusterConfig) (rules map[string]*RuleSet, err error)
	GenerateRulesForNodes(node types.Node, config *types.ClusterConfig, useWeightedService bool) (map[string]*RuleSet, error)
	Merge(subset, wholeset map[string]*RuleSet) (rules map[string]*RuleSet, removals int, err error)

	BaseChain() string
}

type iptables struct {
	chain     util.Chain
	masqChain util.Chain
	table     util.Table

	iptables util.Interface

	masq bool

	// cli flag to exclude packets where the client ip is in this cidr range
	podCidrMasq string

	ctx     context.Context
	logger  logrus.FieldLogger
	metrics iptablesMetrics
}

func NewIPTables(ctx context.Context, lbKind, configKey, podCidrMasq, chain string, masq bool, logger logrus.FieldLogger) (IPTables, error) {
	return &iptables{
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

func (i *iptables) Flush() error {
	// Make several attempts to flush the chain.  Warn on failures.
	var err error
	idx, tries := 0, 5

	// emit a metric about the flush
	start := time.Now()
	defer func() {
		i.metrics.IPTables("flush", idx, err, time.Now().Sub(start))
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

func (i *iptables) Save() (map[string]*RuleSet, error) {
	var err error
	var b []byte
	start := time.Now()
	defer func() {
		i.metrics.IPTables("save", 1, err, time.Now().Sub(start))
	}()

	b, err = i.iptables.Save(i.table)
	if err != nil {
		return nil, err
	}
	return i.rulesFromBytes(b)
}

func (i *iptables) Restore(rules map[string]*RuleSet) error {
	var err error
	start := time.Now()
	defer func() {
		i.metrics.IPTables("restore", 1, err, time.Now().Sub(start))
	}()
	b := BytesFromRules(rules)
	// must restore counters; must ? flush
	err = i.iptables.Restore(i.table, b, !util.NoFlushTables, !util.NoRestoreCounters)
	return err
}

func (i *iptables) Merge(subset, wholeset map[string]*RuleSet) (map[string]*RuleSet, int, error) {
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

// generates a ruleset for only kube-ipvs.  a different function ought to merge these
// XXX chain rule
func (i *iptables) GenerateRules(config *types.ClusterConfig) (map[string]*RuleSet, error) {
	out := map[string]*RuleSet{
		"PREROUTING": &RuleSet{
			ChainRule: ":PREROUTING ACCEPT",
			Rules: []string{
				"-A PREROUTING -j " + i.chain.String(),
			},
		},
		i.masqChain.String(): &RuleSet{
			ChainRule: fmt.Sprintf(":%s - [0:0]", i.masqChain.String()),
			Rules: []string{
				i.generateMasqRule(),
			},
		},
		i.chain.String(): &RuleSet{
			ChainRule: ":" + i.chain.String() + " - [0:0]",
		},
	}

	// format strings for masq and jump rules
	masqFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %s -m %s --dport %%s -m comment --comment "%%s" -j %s`, i.chain, i.masqChain)
	jumpFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %s -m %s --dport %%s -m comment --comment "%%s" -j %%s`, i.chain)

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

	for _, chain := range out {
		for _, r := range chain.Rules {
			fmt.Println("generateRules():", r)
		}
	}
	return out, nil
}

func (i *iptables) GenerateRulesForNodes(node types.Node, config *types.ClusterConfig, useWeightedService bool) (map[string]*RuleSet, error) {
	out := map[string]*RuleSet{
		"PREROUTING": &RuleSet{
			ChainRule: ":PREROUTING ACCEPT",
			Rules: []string{
				"-A PREROUTING -j " + i.chain.String(),
			},
		},
		i.masqChain.String(): &RuleSet{
			ChainRule: fmt.Sprintf(":%s - [0:0]", i.masqChain.String()),
			Rules: []string{
				i.generateMasqRule(),
			},
		},
		i.chain.String(): &RuleSet{
			ChainRule: ":" + i.chain.String() + " - [0:0]",
		},
	}

	// format strings for masq and jump rules
	masqFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %s -m %s --dport %%s -m comment --comment "%%s" -j %s`, i.chain, i.masqChain)
	jumpFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %s -m %s --dport %%s -m comment --comment "%%s" -j %%s`, i.chain)
	weightedJumpFmt := fmt.Sprintf(`-A %s -d %%s/32 -p %s -m %s --dport %%s -m comment --comment "%%s"  -m statistic --mode random --probability %%0.11f -j %%s`, i.chain)

	// walk the service configuration and apply all rules
	rules := []string{}
	for serviceIP, services := range config.Config {
		dest := string(serviceIP)
		for dport, service := range services {
			protocols := getServiceProtocols(service.TCPEnabled, service.UDPEnabled)
			// iterate ogetServiceProtocolsver node endpoints to see if this service is running on the node
			if !node.HasServiceRunning(service.Namespace, service.Service, service.PortName) {
				continue
			}

			ident := types.MakeIdent(service.Namespace, service.Service, service.PortName)

			for _, prot := range protocols {
				chain := ravelServicePortChainName(ident, prot, i.chain.String())
				if i.masq {
					rules = append(rules, fmt.Sprintf(masqFmt, dest, prot, prot, dport, ident))
				}
				nodeProbability := node.GetLocalServicePropability(service.Namespace, service.Service, service.PortName, i.logger)
				if useWeightedService {
					i.logger.Debugf("probability=%v ident=%v", nodeProbability, ident)
					rules = append(rules, fmt.Sprintf(weightedJumpFmt, dest, prot, prot, dport, ident, nodeProbability, chain))
				} else {
					rules = append(rules, fmt.Sprintf(jumpFmt, dest, prot, prot, dport, ident, chain))
				}
			}

		}
	}

	// sort and add to output
	// sort.Sort(sort.StringSlice(rules))
	out[i.chain.String()].Rules = rules

	// create the service chains for each endpoint with probability of calling endpoint emulating WRR
	// walk the service configuration and apply all rules
	for _, services := range config.Config {
		for _, service := range services {
			// iterate over node endpoints to see if this service is running on the node
			if !node.HasServiceRunning(service.Namespace, service.Service, service.PortName) {
				continue
			}
			protocols := getServiceProtocols(service.TCPEnabled, service.UDPEnabled)
			ident := types.MakeIdent(service.Namespace, service.Service, service.PortName)
			for _, prot := range protocols {
				chain := ravelServicePortChainName(ident, prot, i.chain.String())

				// pass if already configured
				if _, ok := out[chain]; ok {
					continue
				}

				portNumber := node.GetPortNumber(service.Namespace, service.Service, service.PortName)
				serviceRules := []string{}

				podIPs := node.GetPodIPs(service.Namespace, service.Service, service.PortName)
				l := len(podIPs)
				for n, ip := range podIPs {
					sepChain := ravelServiceEndpointChainName(ident, ip, prot, i.chain.String())
					probFmt := computeServiceEndpointString(chain, ident, sepChain, l, n)

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
				}

			}

		}
	}

	for _, chain := range out {
		for _, rule := range chain.Rules {
			fmt.Println("rule:", rule)
		}
	}

	return out, nil
}

func (i *iptables) BaseChain() string {
	return i.chain.String()
}

func (i *iptables) rulesFromBytes(b []byte) (map[string]*RuleSet, error) {
	return GetSaveLines(i.table, b)
}

func (i *iptables) generateMasqRule() string {
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
		// Loop through the rules of the chains kube rule
		for _, rule := range kubeRule.Rules {
			// Append the rule to the string
			iptablesLines = append(iptablesLines, rule)
		}
	}

	// Finish with the commit at the end (newline after COMMIT required)
	iptablesLines = append(iptablesLines, "COMMIT\n")

	return []byte(strings.Join(iptablesLines, "\n"))
}
