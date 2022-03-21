package system

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/Comcast/Ravel/pkg/types"
)

// TODO - DEBUG remove when not pinning to debug
func init() {
	log.SetLevel(log.DebugLevel)
}

type IPVS struct {
	nodeIP string

	ignoreCordon   bool
	weightOverride bool
	defaultWeight  int

	ctx    context.Context
	logger log.FieldLogger
}

// NewIPVS creates a new IPVS struct which manages ipvsadm
func NewIPVS(ctx context.Context, primaryIP string, weightOverride bool, ignoreCordon bool, logger log.FieldLogger) (*IPVS, error) {
	log.Debugln("ipvs: Creating new IPVS manager")
	return &IPVS{
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
func (i *IPVS) Get() ([]string, error) {

	startTime := time.Now()
	defer func() {
		log.Debugln("ipvs: Get run time:", time.Since(startTime))
	}()

	// run the ipvsadm command
	// log.Debugln("ipvs: Get(): Running ipvsadm -Sn")

	cmdCtx, cmdContextCancel := context.WithTimeout(i.ctx, time.Second*20)
	defer cmdContextCancel()

	cmd := exec.CommandContext(cmdCtx, "ipvsadm", "-Sn")
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ipvs: ipvsadm -Sn failed with %v", err)
	}

	out := []string{}
	buf := bytes.NewBuffer(stdout)
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		rule := scanner.Text()
		/*
			filter only ipv4 rules
			this looks janky, until you consider the ipvsadm source code, whose output this method consumes
			http://svn.linuxvirtualserver.org/repos/ipvsadm/trunk/ipvsadm.c
			if (buf[0] == '[') {
				buf++;
				portp = strchr(buf, ']');
				if (portp == NULL)
				...

			the accepted way to parse whether a rule is v6 in LVS is "look along
			the string until you see a closing bracket". Good enough for Linus, good enough for me...
		*/
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
func (i *IPVS) GetV6() ([]string, error) {
	startTime := time.Now()
	defer func() {
		log.Debugln("ipvs: GetV6 run time:", time.Since(startTime))
	}()

	log.Debugln("ipvs: GetV6: Running ipvsadm -Sn")

	cmdCtx, cmdContextCancel := context.WithTimeout(i.ctx, time.Second*20)
	defer cmdContextCancel()

	// run the ipvsadm command
	cmd := exec.CommandContext(cmdCtx, "ipvsadm", "-Sn")
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ipvs: ipvsadm -Sn failed with %v", err)
	}

	out := []string{}
	buf := bytes.NewBuffer(stdout)
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		rule := scanner.Text()
		// filter only v6 rules
		// this looks janky, until <see comment on GetV4 above
		if strings.Contains(rule, "[") && strings.Contains(rule, "]") {
			out = append(out, rule)
		}
	}

	return out, nil
}

func (i *IPVS) Set(rules []string) ([]byte, error) {

	startTime := time.Now()
	defer func() {
		log.Debugln("ipvs: Set run time:", time.Since(startTime))
	}()

	// log.Debugln("ipvs: Set(): Running ipvsadm -R")

	log.Debugf("ipvs: setting %d ipvs rules", len(rules))

	// DEBUG - output rules involving 5016
	for _, r := range rules {
		if strings.Contains(r, "5016") {
			log.Debugln("ipvs: SETTING 5016 RULE WITH IPVSADM:", r)
		}
	}

	cmdCtx, cmdContextCancel := context.WithTimeout(i.ctx, time.Minute)
	defer cmdContextCancel()

	// run the ipvsadm command
	cmd := exec.CommandContext(cmdCtx, "ipvsadm", "-R")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("ipvs: ipvsadm -R failed with %v", err)
	}
	defer stdin.Close()

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b

	input := strings.Join(rules, "\n")
	// log.Debugln("ipvs: inputting ipvsadm rules:", input)
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	io.WriteString(stdin, input)
	stdin.Close()
	// log.Debugln("ipvs: done inputting ipvsadm rules")
	return b.Bytes(), cmd.Wait()
}

func (i *IPVS) Teardown(ctx context.Context) error {
	log.Debugln("ipvs: Teardown: Running ipvsadm -C")

	cmdCtx, cmdContextCancel := context.WithTimeout(ctx, time.Second*20)
	defer cmdContextCancel()

	cmd := exec.CommandContext(cmdCtx, "ipvsadm", "-C")
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
func (i *IPVS) generateRules(nodes types.NodesList, config *types.ClusterConfig) ([]string, error) {
	rules := []string{}

	startTime := time.Now()
	defer func() {
		log.Debugln("ipvs: generateRules run time:", time.Since(startTime))
	}()

	for vip, ports := range config.Config {

		// vipStartTime := time.Now()
		// log.Debugln("ipvs: generating ipvs rules from ClusterConfig for vip", vip)

		// Add rules for Frontend ipvsadm
		for port, serviceConfig := range ports {

			// DEBUG - trace port 5016
			if port == "5016" {
				log.Debugln("ipvs: 5016 found in cluster config rules when generating ipvs rules:", serviceConfig)
			}

			// log.Debugln("ipvs: The scheduler for service", serviceConfig.Service, serviceConfig.PortName, "is set to", serviceConfig.IPVSOptions.Scheduler())
			// log.Debugln("ipvs: The raw scheduler for service", serviceConfig.Service, serviceConfig.PortName, "is set to", serviceConfig.IPVSOptions.RawScheduler)

			// If we have the scheduler set to `mh`, and flags are blank, then set flag-1,flag-2.
			// This prevents dropped packets when maglev is used.
			if serviceConfig.IPVSOptions.Scheduler() == "mh" && serviceConfig.IPVSOptions.Flags == "" {
				log.Infoln("ipvs: Assuming flag-1,flag-2 for mh scheduler without flags.  Name:", serviceConfig.Service)
				serviceConfig.IPVSOptions.Flags = "flag-1,flag-2"
			}

			// log.Debugln("ipvs: generating ipvs rule for", port, serviceConfig)
			// set rules for tcp / udp
			if serviceConfig.TCPEnabled {
				rule := fmt.Sprintf(
					"-A -t %s:%s -s %s",
					vip,
					port,
					serviceConfig.IPVSOptions.Scheduler(),
				)

				// flags default empty; only append if we have arguments
				if serviceConfig.IPVSOptions.Flags != "" {
					rule = fmt.Sprintf("%s -b %s", rule, serviceConfig.IPVSOptions.Flags)
				}

				// log.Debugln("ipvs: Generated IPVS rule:", rule)
				rules = append(rules, rule)
			}

			if serviceConfig.UDPEnabled {
				// log.Debugln("ipvs: generating udp ipvs rule for", port, serviceConfig)
				rule := fmt.Sprintf(
					"-A -u %s:%s -s %s",
					vip,
					port,
					serviceConfig.IPVSOptions.Scheduler(),
				)

				// flags default empty; only append if we have arguments
				if serviceConfig.IPVSOptions.Flags != "" {
					rule = fmt.Sprintf("%s -b %s", rule, serviceConfig.IPVSOptions.Flags)
				}

				// log.Debugln("ipvs: Generated IPVS rule:", rule)
				rules = append(rules, rule)
			}
		}
		// log.Debugln("ipvs: Generated IPVS rules for vip:", vip, "took", time.Since(vipStartTime))
	}

	// filter to just eligible nodes. right now this can be done at the
	// outer scope, but if nodes are to be filtered on the basis of endpoints,
	// this functionality may need to move to the inner loop.
	eligibleNodes := types.NodesList{}
	for _, node := range nodes {
		eligible, reason := node.IsEligibleBackendV4(config.NodeLabels, i.nodeIP, i.ignoreCordon)
		if !eligible {
			log.Debugf("ipvs: node %s deemed ineligible. %v", i.nodeIP, reason)
			continue
		}
		eligibleNodes = append(eligibleNodes, node)
	}

	// Next, we iterate over vips, ports, _and_ nodes to create the backend definitions
	for vip, ports := range config.Config {
		// log.Debugln("ipvs: generating backend ipvs rules from ClusterConfig for vip", vip)

		// Now iterate over the whole set of services and all of the nodes for each
		// service writing ipvsadm rules for each element of the full set
		for port, serviceConfig := range ports {
			if port == "5016" {
				log.Debugln("ipvs: 5016 found in cluster config rules when generating ipvs backend definitions:", serviceConfig, "weight override:", i.weightOverride, "default weight", i.defaultWeight, "eligible nodes:", eligibleNodes)
			}
			// log.Debugln("ipvs: generating ipvs rule for", port)
			nodeSettings := getNodeWeightsAndLimits(eligibleNodes, serviceConfig, i.weightOverride, i.defaultWeight)
			for _, n := range eligibleNodes {
				// log.Debugln("ipvs: generating backend ipvs rule for node", n.Name, "at address", n.Addresses)
				// ipvsadm -a -t $VIP_ADDR:<port> -r $backend:<port> -g -w 1 -x 0 -y 0

				if serviceConfig.TCPEnabled {
					rule := fmt.Sprintf(
						"-a -t %s:%s -r %s:%s -%s -w %d -x %d -y %d",
						vip, port,
						n.IPV4(), port,
						nodeSettings[n.IPV4()].forwardingMethod,
						nodeSettings[n.IPV4()].weight,
						nodeSettings[n.IPV4()].uThreshold,
						nodeSettings[n.IPV4()].lThreshold,
					)

					if strings.Contains(rule, "5016") {
						log.Debugln("ipvs: Generated 5016 tcp rule for node", n.Name, "-", rule)
					}

					// log.Debugln("ipvs: Generated backend IPVS rule:", rule)
					rules = append(rules, rule)
				}

				if serviceConfig.UDPEnabled {
					rule := fmt.Sprintf(
						"-a -u %s:%s -r %s:%s -%s -w %d -x %d -y %d",
						vip, port,
						n.IPV4(), port,
						nodeSettings[n.IPV4()].forwardingMethod,
						nodeSettings[n.IPV4()].weight,
						nodeSettings[n.IPV4()].uThreshold,
						nodeSettings[n.IPV4()].lThreshold,
					)

					// log.Debugln("ipvs: Generated IPVS V6 rule:", rule)
					rules = append(rules, rule)
				}
			}
		}
		// log.Debugln("ipvs: Generated IPVS rules for vip:", vip)
	}

	sort.Sort(ipvsRules(rules))
	return rules, nil
}

// generateRules takes a list of nodes and a clusterconfig and creates a complete
// set of IPVS rules for application.
// In order to accept IPVS Options, what do we do?
// NOTE: As of this writing 3/27/20, we use HAProxy to NAT to the v4 network,
// but HAProxy does not support UDP. Leaving this here as it correctly sets v6
// UDP servers, but if a backend is a realserver node translating with haproxy,
// traffic won't get through
func (i *IPVS) generateRulesV6(nodes types.NodesList, config *types.ClusterConfig) ([]string, error) {
	rules := []string{}

	startTime := time.Now()
	defer func() {
		log.Debugln("ipvs: generateRules IPv6 run time:", time.Since(startTime))
	}()

	for vip, ports := range config.Config6 {
		// Add rules for Frontend ipvsadm as tcp / udp
		for port, serviceConfig := range ports {

			// If we have the scheduler set to `mh`, and flags are blank, then set flag-1,flag-2.
			// This prevents dropped packets when maglev is used.
			if serviceConfig.IPVSOptions.Scheduler() == "mh" && serviceConfig.IPVSOptions.Flags == "" {
				serviceConfig.IPVSOptions.Flags = "flag-1,flag-2"
				// log.Debugln("v6 ipvs: The scheduler for service", serviceConfig.Service, serviceConfig.PortName, "is set to", serviceConfig.IPVSOptions.Scheduler())
				// log.Debugln("v6 ipvs: The raw scheduler for service", serviceConfig.Service, serviceConfig.PortName, "is set to", serviceConfig.IPVSOptions.RawScheduler)
			}

			// set rules for tcp / udp
			if serviceConfig.TCPEnabled {
				rule := fmt.Sprintf(
					"-A -t [%s]:%s -s %s",
					vip,
					port,
					serviceConfig.IPVSOptions.Scheduler(),
				)

				// flags default empty; only append if we have arguments
				if serviceConfig.IPVSOptions.Flags != "" {
					rule = fmt.Sprintf("%s -b %s", rule, serviceConfig.IPVSOptions.Flags)
				}

				rules = append(rules, rule)
			}

			if serviceConfig.UDPEnabled {
				rule := fmt.Sprintf(
					"-A -u [%s]:%s -s %s",
					vip,
					port,
					serviceConfig.IPVSOptions.Scheduler(),
				)

				// flags default empty; only append if we have arguments
				if serviceConfig.IPVSOptions.Flags != "" {
					rule = fmt.Sprintf("%s -b %s", rule, serviceConfig.IPVSOptions.Flags)
				}

				// log.Debugln("ipvs: Generated IPVS V6 rule:", rule, "for vip", vip)
				rules = append(rules, rule)
			}
		}
	}

	// filter to just eligible nodes. right now this can be done at the
	// outer scope, but if nodes are to be filtered on the basis of endpoints,
	// this functionality may need to move to the inner loop.
	eligibleNodes := types.NodesList{}
	for _, node := range nodes {
		eligible, _ := node.IsEligibleBackendV6(config.NodeLabels, i.nodeIP, i.ignoreCordon)
		if !eligible {
			// log.Debugf("ipvs: node %s deemed ineligible as ipv6 backend. %v\r\n", i.nodeIP, reason)
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
				if serviceConfig.TCPEnabled {
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

				if serviceConfig.UDPEnabled {
					rule := fmt.Sprintf(
						"-a -u [%s]:%s -r [%s]:%s -%s -w %d -x %d -y %d",
						vip, port,
						n.IPV6(), port,
						nodeSettings[n.IPV6()].forwardingMethod,
						nodeSettings[n.IPV6()].weight,
						nodeSettings[n.IPV6()].uThreshold,
						nodeSettings[n.IPV6()].lThreshold,
					)
					// log.Debugln("ipvs: Generated IPVS V6 rule:", rule)
					rules = append(rules, rule)
				}
			}
		}
	}
	sort.Sort(ipvsRules(rules))
	return rules, nil
}

func (i *IPVS) SetIPVS(nodes types.NodesList, config *types.ClusterConfig, logger log.FieldLogger) error {

	startTime := time.Now()
	defer func() {
		log.Debugln("ipvs: setIPVS run time was:", time.Since(startTime))
	}()

	// log.Debugln("ipvs: Setting IPVS rules")

	// get existing rules
	// log.Debugln("ipvs: getting existing rules")
	ipvsConfigured, err := i.Get()
	if err != nil {
		return err
	}

	// DEBUG - output configurations involving 5016 for tracing
	for _, r := range ipvsConfigured {
		if strings.Contains(r, "5016") {
			log.Debugln("ipvs: 5016 rule found in existing IPVS rule:", r)
		}
	}

	// get config-generated rules
	// log.Debugln("ipvs: start generating rules after", time.Since(startTime))
	ipvsGenerated, err := i.generateRules(nodes, config)
	if err != nil {
		return err
	}
	// log.Debugln("ipvs: done generating rules after", time.Since(startTime))

	// DEBUG - output configurations involving 5016 for tracing
	for _, r := range ipvsGenerated {
		if strings.Contains(r, "5016") {
			log.Debugln("ipvs: 5016 rule found in generated IPVS rule:", r)
		}
	}

	// generate a set of deletions + creations
	// log.Debugln("ipvs: start merging rules after", time.Since(startTime))
	rules := i.merge(ipvsConfigured, ipvsGenerated)
	if len(rules) > 0 {
		log.Debugln("ipvs: setting", len(rules), "ipvsadm rules")
		setBytes, err := i.Set(rules)
		if err != nil {
			log.Errorf("ipvs: error calling ipvs. Set: %v/%v\r\n", string(setBytes), err)
			for _, rule := range rules {
				log.Errorf("ipvs: rules failed to apply: %s\n", rule)
			}
			return err
		}
	}

	// log.Debugln("ipvs: done merging rules after", time.Since(startTime))
	// log.Debugln("ipvs: done merging and applying rules")
	return nil
}

func (i *IPVS) SetIPVS6(nodes types.NodesList, config *types.ClusterConfig, logger log.FieldLogger) error {

	startTime := time.Now()
	defer func() {
		log.Debugln("ipvs: setIPVS v6 run time:", time.Since(startTime))
	}()

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
	// log.Debugln("ipvs: merging v6 rules")
	rules := i.merge(ipvsConfigured, ipvsGenerated)

	if len(rules) > 0 {
		setBytes, err := i.Set(rules)
		if err != nil {
			logger.Errorf("ipvs: error calling ipvs.Set. %v/%v", string(setBytes), err)
			for _, rule := range rules {
				log.Errorf("ipvs: Error setting IPVS rule: %s\n", rule)
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

	// DEBUG
	if strings.Contains(serviceConfig.Service, "graceful") {
		log.Debugln("ipvs: getNodeWeightsAndLimits - found 5016 service calculating node weights and limits.  Weight override was:", weightOverride)
	}

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
			// DEBUG
			if strings.Contains(serviceConfig.Service, "graceful") {
				log.Debugln("ipvs: getNodeWeightsAndLimits - 5016 service called getWeightForNode", node.Name, serviceConfig.Service, "and got", weight)
				log.Debugln("ipvs: getNodeWeightsAndLimits - 5016 node", node.Name, "has", len(node.Endpoints), "endpoints")
			}
		}

		cfg := nodeConfig{
			forwardingMethod: serviceConfig.IPVSOptions.ForwardingMethod(),
			weight:           weight,
			uThreshold:       perNodeX,
			lThreshold:       perNodeY,
		}

		// DEBUG
		if strings.Contains(serviceConfig.Service, "graceful") {
			log.Debugln("ipvs: getNodeWeightsAndLimits - 5016 service setting node weight for node", node.Name, "to", cfg.weight)
		}

		nodeWeights[node.IPV4()] = cfg
		nodeWeights[node.IPV6()] = cfg
	}

	// DEBUG
	if strings.Contains(serviceConfig.Service, "graceful") {
		for k, v := range nodeWeights {
			log.Debugln("ipvs: 5016 getNodeWeightsAndLimits determined that the node", k, "has a weight of", v.weight)
		}
	}
	return nodeWeights
}

func getWeightForNode(node types.Node, serviceConfig *types.ServiceDef) int {
	weight := 0
	if strings.Contains(serviceConfig.Service, "graceful") && (node.Name == "10.131.153.76" || node.Name == "10.131.153.81") {
		log.Debugln("ipvs: getWeightForNode 5016 iterating over", len(node.Endpoints), "node endpoints for node")
	}
	for _, ep := range node.Endpoints {
		if ep.Namespace != serviceConfig.Namespace || ep.Service != serviceConfig.Service {
			continue
		}
		if strings.Contains(serviceConfig.Service, "graceful") {
			log.Debugln("ipvs: getWeightForNode 5016 evaluating subsets", ep.Subsets, "against service port name", serviceConfig.PortName)
		}
		for _, subset := range ep.Subsets {
			for _, port := range subset.Ports {
				if strings.Contains(serviceConfig.Service, "graceful") {
					log.Debugln("ipvs: getWeightForNode 5016 graceful service being compared to node port", port.Name, serviceConfig.PortName)
				}
				if port.Name == serviceConfig.PortName {

					// DEBUG
					if strings.Contains(serviceConfig.Service, "graceful") {
						log.Debugln("ipvs: getNodeWeightsAndLimits - found 5016 subset for weighting on node", node.Name, "adding weight", len(subset.Addresses), "and addresses", subset.Addresses)
					}

					weight += len(subset.Addresses)
					break
				}
			}
		}
	}

	// DEBUG
	if strings.Contains(serviceConfig.Service, "graceful") {
		log.Debugln("ipvs: getNodeWeightsAndLimits - found 5016 service calculating weight for node", node.Name, "as", weight)
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
func (i *IPVS) merge(existingRules, newRules []string) []string {

	// DEBUG - display all rules for creating test cases and such
	// for _, r := range configured {
	// log.Debugln(r)
	// }
	// log.Debugln("ipvs: -- ", len(generated), "Generated rules")
	// for _, r := range generated {
	// log.Debugln(r)
	// }

	// mergedRules will be the final set of merged rules we produce
	var mergedRules []string

	// First, filter out rules that already exist from the generated rules
	for _, newRule := range newRules {
		var skipNewRule bool
		for _, existingRule := range existingRules {
			if i.sanitizeIPVSRule(existingRule) == i.sanitizeIPVSRule(newRule) {
				skipNewRule = true
				break
			}
		}

		if !skipNewRule {
			// only add this generated rule if a rule is already set
			log.Println("new rule:", newRule)
			mergedRules = append(mergedRules, newRule)
		}
	}

	// Next, we convert any add rules to edit rules if they already exist
	// but need modified in place instead
	for _, existingRule := range existingRules {
		for n, mergedRule := range mergedRules {
			// This just might be a weight changing: "-a -t 10.54.213.253:5678 -r 10.54.213.246:5678 -i -w X"
			// where the "X" is different between configured and generated.
			// These rules are fetched using "ipvsadm -Sn" if you want to fetch them manually
			if i.rulesMatchExceptWeights(existingRule, mergedRule) {
				log.Println("convert to edit:", mergedRules[n])
				mergedRules[n] = strings.Replace(mergedRule, "-a", "-e", 1)
				continue
			}
		}
	}

	// Finally, we generate removals for rules that exist already, but were not in the new generation
	// and add them to the generated rules
	for _, existingRule := range existingRules {
		var foundRule bool
		for _, newRule := range newRules {
			if i.rulesHaveMatchingVIPAndBackend(existingRule, newRule) {
				// skip this rule set because it still exists in the new rules
				foundRule = true
				break
			}
		}
		if !foundRule {
			// make a delete for this existingRule and add it to the mergedRules
			// because this item needs removed
			newDeleteRule := i.createDeleteRuleFromAddRule(existingRule)
			log.Debugln("delete rule:", newDeleteRule, "from", existingRule)
			mergedRules = append(mergedRules, newDeleteRule)
		}
	}

	// fixup maglev mh-port,mh-fallback rules
	mergedRules = i.fixMaglevFlagsOnRules(mergedRules)

	log.Debugln("ipvs: --", len(existingRules), "existing rules, vs", len(newRules), "newly generated rules. merged these down to", len(mergedRules), "rules")
	return mergedRules
}

// createDeleteRuleFromAddRule creates an IPVS delete rule from an add rule.
// this takes a rule like this:
//  ipvsadm -a -t 10.131.153.120:8889 -s mh -b flag-1,flag-2
// and turns it into a delete rule like this:
//  ipvsadm -d -t 10.131.153.120:8889
func (i IPVS) createDeleteRuleFromAddRule(addRule string) string {

	addRule = strings.Replace(addRule, "-A", "-D", 1)
	addRule = strings.Replace(addRule, "-a", "-d", 1)
	addRule = strings.TrimSpace(addRule)

	// split the add rule at the `-s` to remove the scheduler
	ruleChunks := strings.Split(addRule, " -s")
	if len(ruleChunks) >= 1 {
		return ruleChunks[0]
	}
	return addRule
}

// fixMaglevFlags fixes the maglev flag strings on rules so they can be applied
func (i *IPVS) fixMaglevFlagsOnRules(rules []string) []string {
	fixedRules := []string{}
	for _, v := range rules {
		fixedRule := strings.Replace(v, "mh-fallback", "flag-1", -1)
		fixedRule = strings.Replace(fixedRule, "mh-port", "flag-2", -1)
		fixedRules = append(fixedRules, fixedRule)
	}
	return fixedRules
}

// rulesHaveMatchingVIPAndBackend checks if two rules are similar enough in that they
// both reference the same VIP and backend target.  Ignores weights and other
// settings on the VIP such as adding, or editing
func (i *IPVS) rulesHaveMatchingVIPAndBackend(ruleA string, ruleB string) bool {

	// sanitize both rules and go further by removing the -a or -e prefix as well
	ruleA = i.sanitizeIPVSRule(ruleA)
	ruleA = strings.TrimPrefix(ruleA, "-a")
	ruleA = strings.TrimPrefix(ruleA, "-A")
	ruleA = strings.TrimPrefix(ruleA, "-e")
	ruleA = strings.TrimSpace(ruleA)
	ruleB = i.sanitizeIPVSRule(ruleB)
	ruleB = strings.TrimPrefix(ruleB, "-a")
	ruleB = strings.TrimPrefix(ruleB, "-A")
	ruleB = strings.TrimPrefix(ruleB, "-e")
	ruleB = strings.TrimSpace(ruleB)

	// break the rules at their weight and compare the first chunk (non weighted) chunk
	ruleASplit := strings.Split(ruleA, "-w ")
	ruleBSplit := strings.Split(ruleB, "-w ")

	// DEBUG
	if strings.Contains(ruleA, "10.131.153.120:8889") {
		log.Println(ruleASplit[0], "---", ruleBSplit[0])
	}

	// if the rules both have two chunks and their first chunks are equal, then they match
	if len(ruleBSplit) > 0 && len(ruleASplit) > 0 {
		// check if the base part of the rules match. If they do, then these rules
		// both reference the same VIP and target, so they are equal.
		if ruleBSplit[0] == ruleASplit[0] {
			// DEBUG
			if strings.Contains(ruleA, "10.131.153.120:8889") {
				log.Println("MATCH FOUND")
			}
			return true
		}
	}

	// DEBUG
	if strings.Contains(ruleA, "10.131.153.120:8889") {
		log.Println("DO NOT MATCH")
	}

	return false
}

// sanitizeIPVSRule strips out various differences between existing and
// generated IPVS rules so that they can more easily be compaired.
// this includes removing '--tun-type ipip', as well as '-x 0 -y 0'.
// Also switches mh-fallback and mh-port to flag-1 and flag-2 respectively.
func (i *IPVS) sanitizeIPVSRule(rule string) string {
	rule = strings.TrimSuffix(rule, "-x 0 -y 0")
	rule = strings.TrimSuffix(rule, "-x 0 -y 0")
	rule = strings.TrimSuffix(rule, "--tun-type ipip")
	rule = strings.Replace(rule, "mh-fallback", "flag-1", -1)
	rule = strings.Replace(rule, "mh-port", "flag-2", -1)
	rule = strings.TrimSpace(rule)
	return rule
}

// rulesMatchExceptWeights checks if two rules are equivilent, besides the specific
// weight value they are setting
func (i *IPVS) rulesMatchExceptWeights(existingRule string, newRule string) bool {

	// sanitize both rules so they can be compaired
	existingRule = i.sanitizeIPVSRule(existingRule)
	newRule = i.sanitizeIPVSRule(newRule)

	// break the rule at the -w and see if the first half matches, but the weight half does not
	genAry := strings.Split(newRule, "-w ")
	existingAry := strings.Split(existingRule, "-w ")
	if len(genAry) == 2 && len(existingAry) == 2 {
		// if the first part of the rule before -w is the same, but the second half is
		// different, then we can assume that the weights are changing
		if genAry[0] == existingAry[0] && genAry[1] != existingAry[1] {
			return true
		}
	}
	return false
}

// returns an error if the configurations generated from d.Nodes and d.ConfigMap
// are different than the configurations that are applied in IPVS. This enables for
// nodes and configmaps to be stored declaratively, and for configuration to be
// reconciled outside of a typical event loop.
// addresses passed in as param here must be the set of v4 and v6 addresses
func (i *IPVS) CheckConfigParity(nodes types.NodesList, config *types.ClusterConfig, addresses []string, newConfig bool) (bool, error) {

	startTime := time.Now()
	defer func() {
		log.Debugln("ipvs: CheckConfigParity run time:", time.Since(startTime))
	}()

	// =======================================================
	// == Perform check whether we're ready to start working
	// =======================================================
	if nodes == nil && config == nil {
		log.Debugln("ipvs: CheckConfigParity nodes and config value was nil. configs are the same")
		return true, nil
	}

	if nodes == nil {
		log.Debugln("ipvs: CheckConfigParity nodes was nil. configs not the same")
		return false, nil
	}
	if config == nil {
		log.Debugln("ipvs: CheckConfigParity config was nil. configs not the same")
		return false, nil
	}

	// get desired set of VIP addresses from configuration
	vips := []string{}
	for ip := range config.Config {
		vips = append(vips, string(ip))
	}

	for ip := range config.Config6 {
		vips = append(vips, string(ip))
	}

	// =======================================================
	// == Perform check on ipvs configuration
	// =======================================================
	// pull existing ipvs configurations
	ipvsConfigured, err := i.Get()
	if err != nil {
		return false, fmt.Errorf("ipvs: CheckConfigParity: ipvsConfigured had an error: %w", err)
	}

	// generate desired ipvs configurations
	ipvsGenerated, err := i.generateRules(nodes, config)
	if err != nil {
		// log.Debugln("ipvs: CheckConfigParity: error when generating rules.  not equal")
		return false, fmt.Errorf("ipvs: CheckConfigParity: error generating new IPVS rules: %v", err)
	}

	// compare and return
	// XXX this might not be platform-independent...
	if !compareIPSlices(vips, addresses) {
		log.Debugln("ipvs: CheckConfigParity: VIPS values:", vips)
		log.Debugln("ipvs: CheckConfigParity: Addresses values:", addresses)
		return false, nil
	}

	isEqual := i.ipvsEquality(ipvsConfigured, ipvsGenerated)
	if !isEqual {
		log.Debugln("ipvs: CheckConfigParity: ipvsEquality returned NOT equal")
	} else {
		log.Debugln("ipvs: CheckConfigParity: ipvsEquality returned equal")
	}

	return isEqual, nil
}

// compareIPSlices compares two slices of IP strings in different formats.  The first
// format looks like this:
// 10.131.153.120 2001:558:1044:19c:10ad:ba1a:a83:9979
// the second format looks like this (blanks left intentially):
//             10_131_153_120 10adba1aa839979
// this function can decide if these two string types are equal, even given their
// very different formates
func compareIPSlices(sliceA []string, sliceB []string) bool {
	// loop over A and ensure everything exists in B
	for _, ip := range sliceA {
		exists := compareIPSlicesFindMatch(sliceB, ip)
		if !exists {
			log.Debugln("ipvs: CheckConfigParity: SliceA does not have IP", ip)
			return false
		}
	}

	// loop over B and ensure everything exists in A
	for _, ip := range sliceB {
		exists := compareIPSlicesFindMatch(sliceA, ip)
		if !exists {
			log.Debugln("ipvs: CheckConfigParity: SliceB does not have IP", ip)
			return false
		}
	}

	return true
}

// compareIPSlicesFindMatch finds the specified IP string in the specified
// slice of IPs.  Includes all logic to compare across the formats supported
// by compareIPSlices.
func compareIPSlicesFindMatch(slice []string, ip string) bool {

	// condition the incoming IPs
	ip = compareIPSlicesSanitizeIP(ip)
	if len(ip) == 0 {
		return true // blank ip checks always match
	}

	for _, ipAddr := range slice {
		ipAddr = compareIPSlicesSanitizeIP(ipAddr)

		// skip blank entries in the target slice of IPs
		if len(ipAddr) == 0 {
			continue
		}

		// if the IP is found, then yes, it exists
		if ipAddr == ip {
			return true
		}

		// for IPv6, the formats require us to check the IP as a suffix (the first part of IPv6 is left off)
		// this means there are edge cases where this will incorrectly return true, but this app needs a
		// total re-think to do it better.
		if strings.HasSuffix(ipAddr, ip) {
			return true
		}
		if strings.HasSuffix(ip, ipAddr) {
			return true
		}
	}

	return false
}

// compareIPSlicesSanitizeIP sanitizes an IP so its is comparable between
// the various formats supported by compareIPSlices.
func compareIPSlicesSanitizeIP(ip string) string {
	ip = strings.ReplaceAll(ip, "_", ".")
	ip = strings.ReplaceAll(ip, ":", "")
	ip = strings.ReplaceAll(ip, " ", "")

	// IPv6 IPs are compared via the network adapter name here sometimes.
	// An IPv6 IP of 2001:558:1044:19c:86c2:4b9c:2fd1:7adb will result in an adapter
	// named 86c2b9c2fd17adb , which is the second half of the IPv6 address without
	// colons between its parts.
	if len(ip) > 15 {
		ip = ip[len(ip)-15:]
	}

	return strings.ToLower(ip)
}

// Equality for the IPVS IP addresses currently existing (ipvsConfigured)
// and the IP addresses we want to be configured (ipvsGenerated) means that
// all addresses in ipvsConfigured have to exist in ipvsGenerated.  Compensation
// is made for the desparities in the ipvs commands run and the rules that
// come back from a listing of rules.
func (i *IPVS) ipvsEquality(existingRules []string, newRules []string) bool {

	if len(existingRules) != len(newRules) {
		log.Debugln("ipvs: ipvsEquality: evaluated FALSE due to number of generated vs configured rules")
		return false
	}

	// ensure all new rules exist in the existing rules.  if they don't
	// then these are not equal. if they do, then they are.
	for _, existingRule := range existingRules {
		var found bool
		for _, newRule := range newRules {
			if i.sanitizeIPVSRule(existingRule) == i.sanitizeIPVSRule(newRule) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
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
