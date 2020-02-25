package system

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"

	"github.com/comcast/ravel/pkg/types"
)

const (
	colocationModeDisabled = "disabled"
	colocationModeIPTables = "iptables"
	colocationModeIPVS     = "ipvs"
)

// IPVS is an interface for getting and setting IPVS configurations
type IPVS interface {
	Get() ([]string, error)
	GetV6() ([]string, error)
	Set(rules []string) ([]byte, error)
	Teardown(context.Context) error

	SetIPVS(nodes types.NodesList, config *types.ClusterConfig, logger logrus.FieldLogger) error
	SetIPVS6(nodes types.NodesList, config *types.ClusterConfig, logger logrus.FieldLogger) error
	CheckConfigParity(nodes types.NodesList, config *types.ClusterConfig, addresses []string, configReady bool) (bool, error)
}

type ipvs struct {
	nodeIP string

	ignoreCordon   bool
	weightOverride bool
	defaultWeight  int

	ctx    context.Context
	logger logrus.FieldLogger
}

func NewIPVS(ctx context.Context, primaryIP string, weightOverride bool, ignoreCordon bool, logger logrus.FieldLogger) (IPVS, error) {
	return &ipvs{
		ctx:            ctx,
		nodeIP:         primaryIP,
		logger:         logger,
		weightOverride: weightOverride,
		ignoreCordon:   ignoreCordon,
		defaultWeight:  1, // just so there's no magic numbers to hunt down
	}, nil
}

// =====================================================================================================

// getConfiguredIPVS returns the output of `ipvsadm -Sn`
// That IPVS command returns a list of director VIP addresses sorted in lexicographic order by address:port,
// with backends sorted by realserver address:port.
func (i *ipvs) Get() ([]string, error) {

	// run the ipvsadm command
	cmd := exec.CommandContext(i.ctx, "ipvsadm", "-Sn")
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ipvsadm -Sn failed with %v", err)
	}

	out := []string{}
	buf := bytes.NewBuffer(stdout)
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		rule := scanner.Text()
		// filter away v6 rules
		if !strings.Contains(rule, "[") && !strings.Contains(rule, "]") {
			out = append(out, rule)
		}
	}

	return out, nil
}

// getConfiguredIPVS returns the output of `ipvsadm -Sn`
// That IPVS command returns a list of director VIP addresses sorted in lexicographic order by address:port,
// with backends sorted by realserver address:port.
// GetV6 filters only ipv6 rules. Sadly there is no native ipvsadm command to filter this
func (i *ipvs) GetV6() ([]string, error) {

	// run the ipvsadm command
	cmd := exec.CommandContext(i.ctx, "ipvsadm", "-Sn")
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ipvsadm -Sn failed with %v", err)
	}

	out := []string{}
	buf := bytes.NewBuffer(stdout)
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		rule := scanner.Text()
		// filter only v6 rules
		if strings.Contains(rule, "[") && strings.Contains(rule, "]") {
			out = append(out, rule)
		}
	}

	return out, nil
}

func (i *ipvs) Set(rules []string) ([]byte, error) {

	i.logger.Infof("got %d ipvs rules to set", len(rules))

	// run the ipvsadm command
	cmd := exec.CommandContext(i.ctx, "ipvsadm", "-R")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("ipvsadm -R failed with %v", err)
	}
	defer stdin.Close()

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b

	input := strings.Join(rules, "\n")
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	io.WriteString(stdin, input)
	stdin.Close()
	return b.Bytes(), cmd.Wait()
}

func (i *ipvs) Teardown(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "ipvsadm", "-C")
	return cmd.Run()
}

// XXX this thing needs not only the list of nodes, but also the list of
// endpoints for each service in each node.
//

// TODO: by passing in a list of endpoints, this function can generate weights in
// accordance with the # of pods running on a given node

// generateRules takes a list of nodes and a clusterconfig and creates a complete
// set of IPVS rules for application.
// In order to accept IPVS Options, what do we do?
//
func (i *ipvs) generateRules(nodes types.NodesList, config *types.ClusterConfig) ([]string, error) {
	rules := []string{}

	for vip, ports := range config.Config {
		// Add rules for Frontend ipvsadm
		for port, serviceConfig := range ports {
			rule := fmt.Sprintf(
				"-A -t %s:%s -s %s",
				vip,
				port,
				serviceConfig.IPVSOptions.Scheduler(),
			)
			rules = append(rules, rule)
		}
	}

	// filter to just eligible nodes. right now this can be done at the
	// outer scope, but if nodes are to be filtered on the basis of endpoints,
	// this functionality may need to move to the inner loop.
	eligibleNodes := types.NodesList{}
	for _, node := range nodes {
		eligible, reason := node.IsEligibleBackendV4(config.NodeLabels, i.nodeIP, i.ignoreCordon)
		if !eligible {
			i.logger.Debugf("node %s deemed ineligible. %v", i.nodeIP, reason)
			continue
		}
		eligibleNodes = append(eligibleNodes, node)
	}

	// Next, we iterate over vips, ports, _and_ nodes to create the backend definitions
	for vip, ports := range config.Config {

		// Now iterate over the whole set of services and all of the nodes for each
		// service writing ipvsadm rules for each element of the full set
		for port, serviceConfig := range ports {
			nodeSettings := getNodeWeightsAndLimits(eligibleNodes, serviceConfig, i.weightOverride, i.defaultWeight)
			for _, n := range eligibleNodes {
				// ipvsadm -a -t $VIP_ADDR:<port> -r $backend:<port> -g -w 1 -x 0 -y 0
				rule := fmt.Sprintf(
					"-a -t %s:%s -r %s:%s -%s -w %d -x %d -y %d",
					vip, port,
					n.IPV4(), port,
					nodeSettings[n.IPV4()].forwardingMethod,
					nodeSettings[n.IPV4()].weight,
					nodeSettings[n.IPV4()].uThreshold,
					nodeSettings[n.IPV4()].lThreshold,
				)
				rules = append(rules, rule)
			}
		}
	}
	sort.Sort(ipvsRules(rules))
	return rules, nil
}

// generateRules takes a list of nodes and a clusterconfig and creates a complete
// set of IPVS rules for application.
// In order to accept IPVS Options, what do we do?
//
func (i *ipvs) generateRulesV6(nodes types.NodesList, config *types.ClusterConfig) ([]string, error) {
	rules := []string{}

	for vip, ports := range config.Config6 {
		// Add rules for Frontend ipvsadm
		for port, serviceConfig := range ports {
			rule := fmt.Sprintf(
				"-A -t [%s]:%s -s %s",
				vip,
				port,
				serviceConfig.IPVSOptions.Scheduler(),
			)
			rules = append(rules, rule)
		}
	}

	// filter to just eligible nodes. right now this can be done at the
	// outer scope, but if nodes are to be filtered on the basis of endpoints,
	// this functionality may need to move to the inner loop.
	eligibleNodes := types.NodesList{}
	for _, node := range nodes {
		eligible, reason := node.IsEligibleBackendV6(config.NodeLabels, i.nodeIP, i.ignoreCordon)
		if !eligible {
			i.logger.Debugf("node %s deemed ineligible. %v", i.nodeIP, reason)
			continue
		}
		eligibleNodes = append(eligibleNodes, node)
	}

	// Next, we iterate over vips, ports, _and_ nodes to create the backend definitions
	for vip, ports := range config.Config6 {
		// Now iterate over the whole set of services and all of the nodes for each
		// service writing ipvsadm rules for each element of the full set
		for port, serviceConfig := range ports {
			nodeSettings := getNodeWeightsAndLimits(eligibleNodes, serviceConfig, i.weightOverride, i.defaultWeight)
			for _, n := range eligibleNodes {
				// ipvsadm -a -t $VIP_ADDR:<port> -r $backend:<port> -g -w 1 -x 0 -y 0
				rule := fmt.Sprintf(
					"-a -t [%s]:%s -r [%s]:%s -%s -w %d -x %d -y %d",
					vip, port,
					n.IPV6(), port,
					nodeSettings[n.IPV6()].forwardingMethod,
					nodeSettings[n.IPV6()].weight,
					nodeSettings[n.IPV6()].uThreshold,
					nodeSettings[n.IPV6()].lThreshold,
				)

				rules = append(rules, rule)
			}
		}
	}
	sort.Sort(ipvsRules(rules))
	return rules, nil
}

func (i *ipvs) SetIPVS(nodes types.NodesList, config *types.ClusterConfig, logger logrus.FieldLogger) error {
	// get existing rules
	ipvsConfigured, err := i.Get()
	if err != nil {
		return err
	}

	// get config-generated rules
	ipvsGenerated, err := i.generateRules(nodes, config)
	if err != nil {
		return err
	}

	// generate a set of deletions + creations
	rules := i.merge(ipvsConfigured, ipvsGenerated)
	if len(rules) > 0 {
		setBytes, err := i.Set(rules)
		if err != nil {
			logger.Errorf("error calling ipvs.Set. %v/%v", string(setBytes), err)
			for _, rule := range rules {
				logger.Errorf("Rule :%s:", rule)
			}
			return err
		}
	}
	return nil
}

func (i *ipvs) SetIPVS6(nodes types.NodesList, config *types.ClusterConfig, logger logrus.FieldLogger) error {
	// get existing rules
	ipvsConfigured, err := i.GetV6()
	if err != nil {
		return err
	}

	// get config-generated rules
	ipvsGenerated, err := i.generateRulesV6(nodes, config)
	if err != nil {
		return err
	}

	// generate a set of deletions + creations
	rules := i.merge(ipvsConfigured, ipvsGenerated)

	if len(rules) > 0 {
		setBytes, err := i.Set(rules)
		if err != nil {
			logger.Errorf("error calling ipvs.Set. %v/%v", string(setBytes), err)
			for _, rule := range rules {
				logger.Errorf("Rule :%s:", rule)
			}
			return err
		}
	}
	return nil
}

// nodeconfig stores the ipvs configuraton for a single node.
type nodeConfig struct {
	// forwarding method, weight, u-threshold, and l-threshold
	forwardingMethod string
	weight           int
	uThreshold       int
	lThreshold       int
}

// getNodeWeights returns the relative weighting for each node, and computes
// connection limits based on those weights. currently all nodes have an equal
// weight, so the computation is easy. In the future, when endpoints are considered
// here, perNodeX and perNodeY will be adjusted on the basis of relative weight
func getNodeWeightsAndLimits(nodes types.NodesList, serviceConfig *types.ServiceDef, weightOverride bool, defaultWeight int) map[string]nodeConfig {
	nodeWeights := map[string]nodeConfig{}
	if len(nodes) == 0 {
		return nodeWeights
	}

	perNodeX := serviceConfig.IPVSOptions.UThreshold() / len(nodes)
	perNodeY := serviceConfig.IPVSOptions.LThreshold() / len(nodes)

	// if either of the per-node calcs exceed the limits for ipvs, nuke em both
	if perNodeX > 65535 || perNodeY > 65535 {
		perNodeX, perNodeY = 0, 0
	}

	for _, node := range nodes {
		weight := defaultWeight
		if !weightOverride {
			weight = getWeightForNode(node, serviceConfig)
		}

		cfg := nodeConfig{
			forwardingMethod: serviceConfig.IPVSOptions.ForwardingMethod(),
			weight:           weight,
			uThreshold:       perNodeX,
			lThreshold:       perNodeY,
		}

		nodeWeights[node.IPV4()] = cfg
		nodeWeights[node.IPV6()] = cfg
	}
	return nodeWeights
}

func getWeightForNode(node types.Node, serviceConfig *types.ServiceDef) int {
	weight := 0
	for _, ep := range node.Endpoints {
		if ep.Namespace != serviceConfig.Namespace || ep.Service != serviceConfig.Service {
			continue
		}
		for _, subset := range ep.Subsets {
			found := false
			for _, port := range subset.Ports {
				if port.Name == serviceConfig.PortName {
					found = true
				}
			}
			if !found {
				continue
			}
			weight += len(subset.Addresses)
		}
	}
	return weight
}

// merge takes a set of configured rules and a set of generated rules then
// creates a derived set of rules. The derived rules should only:
// (a) Edit existing "-a" (add a real server) rules if a weight changes
// (b) Delete ("-D") a previous existing virtual service that we no long desire
// (c) Add ("-A") a virtual service that didn't exist before
// (d) Delete ("-d") a realserver that we no longer desire
// (e) Add ("-a") a realserver that didn't previously exist
// The rules-to-apply shouldn't include any rules that don't change,
// which means "appear in both configured and generated rules unchanged".
// This function can modify the array named "generated" - it splices rules out of it
// that already exist (appear in array named "configured")
func (i *ipvs) merge(configured, generated []string) []string {
	// generate full set of rules to apply including deletions
	rules := []string{}
	vsDeletes := []string{}
	rsDeletes := []string{}

	// Check if any existing rules don't have matching generated rules.  If
	// they don't, maybe change the "add" to an "edit" or generate an
	// appropriate delete rule.
	for _, existing := range configured {
		found := false
		for idx, gen := range generated {
			// A generated rule has a "-x N -y M" suffix, which won't appear on
			// a configured rule, at least if N == 0 and M == 0, the defaults.
			// Nevertheless, that generated rule is still equivalent to the
			// configured rule for our purposes. Check for prefix instead of
			// lexical equality.
			if strings.HasPrefix(gen, existing) {
				// While we're here, splice the new rule out of generated[], it already exists.
				generated = append(generated[:idx], generated[idx+1:]...)
				found = true
				break
			} else if strings.HasPrefix(gen, "-a") {
				// This just might be a weight changing: "-a -t 10.54.213.253:5678 -r 10.54.213.246:5678 -i -w X"
				// where the "X" is different between configured and generated.
				// This is pretty brittle, depends heavily on format of output
				// of "ipvsadm -Sn"
				genAry := strings.Split(gen, "-w ")
				existingAry := strings.Split(existing, "-w ")
				if len(genAry) == 2 && len(existingAry) == 2 {
					if genAry[0] == existingAry[0] && genAry[1] != existingAry[1] {
						// Weights are different. Make a "-e" for edit command
						edit := strings.Replace(gen, "-a", "-e", 1)
						i.logger.Debugf("Made -a command into -e command :%s:\n", edit)
						// Remove the "-a" rule from array "generated", on to array "rules"
						generated = append(generated[:idx], generated[idx+1:]...)
						rules = append(rules, edit)
						found = true // don't need to generate a "-d" for this
					}
				}
			}
		}
		if found {
			// existing rule is idential to some generated rule
			// in all relevant (IP:port) aspects, or it ended up as
			// an edit, so don't bother doing anything
			continue
		}
		// Need a deletion rule, as existing rule no longer has a virtual or real
		// server that should get packets routed to it.
		existing = strings.Replace(existing, "-A", "-D", -1)
		existing = strings.Replace(existing, "-a", "-d", -1)
		if strings.HasPrefix(existing, "-D") {
			vsDeletes = append(vsDeletes, strings.Join(strings.Split(existing, " ")[:3], " "))
		} else if strings.HasPrefix(existing, "-d") {
			rsDeletes = append(rsDeletes, strings.Join(strings.Split(existing, " ")[:5], " "))
		}
	}
	// Array "rules" might have "-e" edit commands in it already.
	// Do all the "-d" rules before the "-D" rules, otherwise
	// ipvadm -R says there's a problem.
	if len(rsDeletes) > 0 {
		rules = append(rules, rsDeletes...)
	}
	if len(vsDeletes) > 0 {
		rules = append(rules, vsDeletes...)
	}
	// if any generated rules remain ("-a" or "-A"), append them
	return append(rules, generated...)
}

// returns an error if the configurations generated from d.Nodes and d.ConfigMap
// are different than the configurations that are applied in IPVS. This enables for
// nodes and configmaps to be stored declaratively, and for configuration to be
// reconciled outside of a typical event loop.
// addresses passed in as param here must be the set of v4 and v6 addresses
func (i *ipvs) CheckConfigParity(nodes types.NodesList, config *types.ClusterConfig, addresses []string, newConfig bool) (bool, error) {
	// =======================================================
	// == Perform check whether we're ready to start working
	// =======================================================
	if nodes == nil || config == nil {
		return true, nil
	}

	// get desired set of VIP addresses
	vips := []string{}
	for ip, _ := range config.Config {
		vips = append(vips, string(ip))
	}

	for ip, _ := range config.Config6 {
		vips = append(vips, string(ip))
	}
	sort.Sort(sort.StringSlice(vips))

	// =======================================================
	// == Perform check on ipvs configuration
	// =======================================================
	// pull existing ipvs configurations
	ipvsConfigured, err := i.Get()
	if err != nil {
		return false, err
	}

	// generate desired ipvs configurations
	ipvsGenerated, err := i.generateRules(nodes, config)
	if err != nil {
		return false, fmt.Errorf("generating IPVS rules: %v", err)
	}

	// compare and return
	// XXX this might not be platform-independent...
	if !reflect.DeepEqual(vips, addresses) {
		return false, nil
	}

	return ipvsEquality(ipvsConfigured, ipvsGenerated, newConfig), nil
}

// Equality for the IPVS IP addresses currently existing (ipvsConfigured)
// and the IP addresses we want to be configured (ipvsGenerated) means that
// all addresses in ipvsConfigured have to exist in ipvsGenerated,
// and all addresses in ipvsGenerated have to exist in ipvsConfigured.
// This is like Set Theory's set equality: (A subset of B) and (B subset of A)
// Unfortunately, we have 2 arrays to determine "subset of", and the IP addresses
// don't appear the same way in each array.
func ipvsEquality(ipvsConfigured []string, ipvsGenerated []string, newConfig bool) bool {
	if len(ipvsConfigured) != len(ipvsGenerated) {
		return false
	}
	for _, existing := range ipvsConfigured {
		found := false
		for i, desired := range ipvsGenerated {
			// If it's a brand new configuration, weight don't matter, otherwise, they do
			// weights only appear on "-a" rules
			if newConfig && strings.HasPrefix(desired, "-a") {
				desiredAry := strings.Split(desired, "-w ")
				existingAry := strings.Split(existing, "-w ")
				if desiredAry[0] == existingAry[0] {
					ipvsGenerated = append(ipvsGenerated[:i], ipvsGenerated[i+1:]...)
					found = true
					break
				}
			} else if strings.HasPrefix(desired, existing) { // desired will have "-x 0 -y 0" suffix
				ipvsGenerated = append(ipvsGenerated[:i], ipvsGenerated[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			// the IP address represented by value of "existing" isn't in desired IPs
			return false
		}
	}
	if len(ipvsGenerated) > 0 {
		// There's a new IP address desired that isn't configured
		return false
	}
	return true
}

// ipvsRules is a sortable string array comprised of the output of an ipvsadm -Sn command
// strings within this sortable are expected to match the followinf structure:
//
// action,?,vip,mode,realvip
// -A -t 172.27.223.81:80 -s wlc
// -A -t 172.27.223.81:82 -s wlc
// -a -t 172.27.223.81:82 -r 172.27.223.101:82 -g -w 1
// -a -t 172.27.223.81:82 -r 172.27.223.103:82 -g -w 1
//
// The following precedence rules will be applied:
// if vips dont match then vip < vip
// if mode don't match then s < r
// finally realvip < realvip

type ipvsRules []string

func (r ipvsRules) Len() int      { return len(r) }
func (r ipvsRules) Swap(i, j int) { r[i], r[j] = r[j], r[i] }
func (r ipvsRules) Less(i, j int) bool {
	iTokens := strings.Split(r[i], " ")
	jTokens := strings.Split(r[j], " ")

	if len(iTokens) < 5 || len(jTokens) < 5 {
		return true
	}

	iVIP, iMode, iRealServer := iTokens[2], iTokens[3], iTokens[4]
	jVIP, jMode, jRealServer := jTokens[2], jTokens[3], jTokens[4]

	if iVIP != jVIP {
		// vip addresses are lexicographically ordered,
		// but if they match, precedence is numeric on the basis of port

		// splitting out data to determine whether vips are the same
		iPair := strings.Split(iVIP, ":")
		jPair := strings.Split(jVIP, ":")
		if iPair[0] != jPair[0] {
			return iPair[0] < jPair[0]
		}

		// if the VIP is the same but the port differs, extract the port and compare
		iPort, _ := strconv.Atoi(iPair[1])
		jPort, _ := strconv.Atoi(jPair[1])
		return iPort < jPort
	}
	if iMode != jMode {
		return iMode > jMode // (-s is less than -r)
	}
	return iRealServer < jRealServer
}
