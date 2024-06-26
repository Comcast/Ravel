package system

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Comcast/Ravel/pkg/types"
	"github.com/Comcast/Ravel/pkg/watcher"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

func loadFile (file string) []string {
	results := []string{}
	b, _ := ioutil.ReadFile(file)

	lines := strings.Split(string(b), "\n")
	for _,v := range lines {
		results = append(results, v)
	}
	return results
}

func fileExist (file string) bool {
	_, err := os.Stat(file)
	if err != nil {
		return false
	}
	return true
}

func saveRules (file string, rules []string, suffix string) {
	w, _ := os.Create(file)
	for _, rule := range rules {
		if strings.HasPrefix(rule, "-e") {
			w.WriteString(rule + suffix + "\n")
		} else {
			w.WriteString(rule + "\n")
		}

	}
	w.Close()
}

func CCTest2(t *testing.T, dir string, iter int) {

	log.SetLevel(log.DebugLevel)
	prefix := fmt.Sprintf("%s/%-4.4d-", dir, iter)

    if !fileExist(prefix + "configured") {
		return
	}
	fmt.Println("CCTest", dir, prefix)
	existing := loadFile(prefix + "configured")

	generated := loadFile(prefix + "generated")

	newRules := loadFile(prefix + "newrules")

	ipvs := IPVS{}

	// startTime := time.Now()

	resultingRulesEarly, resultingRulesLate := ipvs.mergeEarlyLate(existing, generated)

	saveRules( prefix + "newrulesEarly.test", resultingRulesEarly, " EARLY")
	saveRules( prefix + "newrulesLate.test", resultingRulesLate, " LATE")

	b, _ := json.MarshalIndent(newRules, "", " ")
	fmt.Println("-----------------------------------------------------")

	fmt.Printf("%s SAVED NEWRULES: %s \n", prefix, string(b))

	b2, _ := json.MarshalIndent(resultingRulesEarly, "", "  ")
	b3, _ := json.MarshalIndent(resultingRulesLate, "", "  ")

	fmt.Printf("%s GENERATED NEWRULES EARLY: %s \n", prefix, string(b2))
	fmt.Printf("%s GENERATED NEWRULES LATE: %s \n", prefix, string(b3))
	fmt.Println("-----------------------------------------------------")

	// t.Log("merged to", len(resultingRulesEarly), "resultingRules in", time.Since(startTime))
}

func CCTest(t *testing.T, dir string) {


	log.SetLevel(log.DebugLevel)

	existing := loadFile(dir + "/01-configured")

	generated := loadFile(dir + "/01-generated")

	newRules := loadFile(dir + "/01-newrules")

	ipvs := IPVS{}

	// startTime := time.Now()

	resultingRules := ipvs.merge(existing, generated)

	saveRules( dir + "/01-newrules.merge", resultingRules, "")

	b, _ := json.MarshalIndent(newRules, "", " ")
	fmt.Println("-----------------------------------------------------")

	fmt.Println("SAVED NEWRULES:\n", string(b))

	b2, _ := json.MarshalIndent(resultingRules, "", "  ")
	fmt.Println("GENERATED NEWRULES:\n", string(b2))
	fmt.Println("-----------------------------------------------------")

	// t.Log("merged to", len(resultingRules), "resultingRules in", time.Since(startTime))
}

func TestCCNewMergeDir(t *testing.T) {

	// CCTest(t, "data1")
	dir := os.Getenv("RULE_DIR")
	if dir == "" {
		dir = "data2"
	}
	for i := 1; i <= 200; i++ {
		CCTest2(t, dir, i)
	}

}


func TestCCNewMerge(t *testing.T) {

	// CCTest(t, "data1")

	CCTest2(t, "data1", 1)
}


func TestMergeRules(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	// load existing rules
	b, err := ioutil.ReadFile("existingRules.json")
	if err != nil {
		t.Fatal(err)
	}
	existingRules := []string{}
	json.Unmarshal(b, &existingRules)

	// load new rules
	b, err = ioutil.ReadFile("newRules.json")
	if err != nil {
		t.Fatal(err)
	}
	newRules := []string{}
	json.Unmarshal(b, &newRules)

	// create a new IPVS object
	ipvs := IPVS{}

	startTime := time.Now()
	resultingRules := ipvs.merge(existingRules, newRules)
	t.Log("merged to", len(resultingRules), "resultingRules in", time.Since(startTime))
	if len(resultingRules) != 20 {
		t.Fatal("incorrect rule count after merging. expected 20. got:", len(resultingRules))
	}
}

func TestGenerateRules(t *testing.T) {
	// nodes []types.Node, config *types.ClusterConfig)

	var testConfig *types.ClusterConfig
	var testNodes []*v1.Node
	w := &watcher.Watcher{}
	b, err := ioutil.ReadFile("../watcher/watcher2.json")
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(b, &w)
	if err != nil {
		t.Fatal(err)
	}

	// load both a test config and nodes from the local disk
	b, err = ioutil.ReadFile("generateRules-nodes.json")
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(b, &testNodes)
	if err != nil {
		t.Fatal(err)
	}

	b, err = ioutil.ReadFile("generateRules-testConfig.json")
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(b, &testConfig)
	if err != nil {
		t.Fatal(err)
	}

	// make an IPVS instance and try to generate rules with the test data we loaded from disk
	i := IPVS{}

	rules, err := i.generateRules(w, testNodes, testConfig)
	if err != nil {
		t.Fatal(err)
	}

	// output the rules created
	t.Log("-- created rules:")
	for _, r := range rules {
		t.Log(r)
	}

	if len(rules) != 6 {
		t.Fatal("incorrect ipvsadm rule count generated")
	}

}

// /app # ipvsadm -Sn
var ipvsadmDump string = `-A -t 172.27.223.81:80 -s wlc
-a -t 172.27.223.81:80 -r 172.27.223.102:80 -g -w 1
-a -t 172.27.223.81:80 -r 172.27.223.103:80 -g -w 1
-A -t 172.27.223.81:82 -s wlc
-a -t 172.27.223.81:82 -r 172.27.223.101:82 -g -w 1
-a -t 172.27.223.81:82 -r 172.27.223.102:82 -g -w 1
-A -t 172.27.223.81:88 -s wlc
-a -t 172.27.223.81:88 -r 172.27.223.101:88 -g -w 1
-A -t 172.27.223.89:8888 -s wlc
-a -t 172.27.223.89:8888 -r 172.27.223.101:8888 -g -w 1
-a -t 172.27.223.89:8888 -r 172.27.223.103:8888 -g -w 1`

func TestCompareIPSlices(t *testing.T) {
	sliceA := []string{"1.2.3.4", "10adba1aa83997b"}
	sliceB := []string{"1.2.3.4", "2001:558:1044:19c:10ad:ba1a:a83:997b"}
	equal := compareIPSlices(sliceA, sliceB)
	if !equal {
		t.Fatal("Slices were not equal but should be")
	}

	sliceA = []string{"1.2.3.4", "10adba1aa83997X"}
	equal = compareIPSlices(sliceA, sliceB)
	if equal {
		t.Fatal("Slices were equal that should not be")
	}
}

func TestIPVSRulesSort(t *testing.T) {
	reference := strings.Split(ipvsadmDump, "\n")

	sorted := ipvsRules(strings.Split(ipvsadmDump, "\n"))
	sort.Sort(sorted)

	for i := range sorted {
		if sorted[i] != reference[i] {
			t.Fatalf("mismatch at index %d. %s!=%s", i, sorted[i], reference[i])
		}
	}
}

func TestMergeIPVSRuleSets(t *testing.T) {
	configured := []string{
		"-A -t 172.27.223.81:80 -s wlc",
		"-a -t 172.27.223.81:80 -r 172.27.223.101:80 -g -w 1",
		"-A -t 172.27.223.81:82 -s wlc",
		"-a -t 172.27.223.81:82 -r 172.27.223.101:82 -g -w 1",
		"-a -t 172.27.223.81:82 -r 172.27.223.103:82 -g -w 1",
	}
	generated := []string{
		"-A -t 172.27.223.81:82 -s wlc",
		"-a -t 172.27.223.81:82 -r 172.27.223.101:82 -g -w 1",
		"-a -t 172.27.223.81:82 -r 172.27.223.103:82 -g -w 1",
	}
	expects := []string{
		"-D -t 172.27.223.81:80",
		"-d -t 172.27.223.81:80 -r 172.27.223.101:80",
		"-A -t 172.27.223.81:82 -s wlc",
		"-a -t 172.27.223.81:82 -r 172.27.223.101:82 -g -w 1",
		"-a -t 172.27.223.81:82 -r 172.27.223.103:82 -g -w 1",
	}

	instance := &IPVS{}
	out := instance.merge(configured, generated)
	for i, rule := range out {
		if rule != expects[i] {
			t.Fatalf("expected rule to match at index %d. %s!=%s", i, rule, expects[i])
		}
	}
}

func TestGetNodeWeightsAndLimits(t *testing.T) {
	// generate a list of 3 nodes
	nodes := []*v1.Node{
		{
			Status: v1.NodeStatus{
				Addresses: []v1.NodeAddress{
					{
						Address: "10.11.12.13",
					},
				},
			},
		},
		{
			Status: v1.NodeStatus{
				Addresses: []v1.NodeAddress{
					{
						Address: "10.11.12.12",
					},
				},
			},
		},
		{
			Status: v1.NodeStatus{
				Addresses: []v1.NodeAddress{
					{
						Address: "10.11.12.11",
					},
				},
			},
		},
	}

	// expects a set of input ipvsoptions to emit a specific nodeconfig
	// we will assert that all nodeconfigs are equal (a valid assumption now, but not later)
	// and we will assert that any nodeconfig is a match for n
	tests := []struct {
		i types.IPVSOptions
		n nodeConfig
		d string
	}{
		{types.IPVSOptions{Flags: "-x 0 -y 0"}, nodeConfig{"g", 1, 0, 0}, "empty set sensible defaults"},
		{types.IPVSOptions{Flags: "-x 6000 -y 3000"}, nodeConfig{"g", 1, 2000, 1000}, "even distribution of conns"},
		{types.IPVSOptions{Flags: "-x 600000 -y 0"}, nodeConfig{"g", 1, 0, 0}, "reset excessive limits"},
		{types.IPVSOptions{RawForwardingMethod: "i", Flags: "-x 60000 -y 0"}, nodeConfig{"i", 1, 20000, 0}, "Y empty"},
		{types.IPVSOptions{Flags: "-x 6 -y 12"}, nodeConfig{"g", 1, 0, 0}, "Y exceeds X"},
		{types.IPVSOptions{Flags: "-x 0 -y 0 bogus"}, nodeConfig{"g", 1, 0, 0}, "bogus F defaults to G"},
	}

	watcher := &watcher.Watcher{
		Nodes: nodes,
	}

	for _, test := range tests {
		sc := &types.ServiceDef{
			IPVSOptions: test.i,
		}
		out := getNodeWeightsAndLimits(nodes, watcher, sc, false, 0)
		if len(out) != len(nodes) {
			t.Fatalf("expected %d nodes. saw %d", len(nodes), len(out))
		}
		for _, node := range out {
			if !reflect.DeepEqual(node, test.n) {
				t.Errorf("expected exact match. %+v / %+v", node, test.n)
			}
		}
	}

}

func TestCreateDeleteRule(t *testing.T) {

	ipvsManager := IPVS{
		logger: logrus.New(),
	}

	tests := []struct {
		addRule            string
		deleteRuleExpected string
	}{
		{
			addRule:            "-a -t 10.131.153.125:71 -r 10.131.153.81:71 -g -w 0",
			deleteRuleExpected: "-d -t 10.131.153.125:71 -r 10.131.153.81:71",
		},
		{
			addRule:            "-a -t 10.131.153.125:8080 -r 10.131.153.76:8080 -i -w 0 --tun-type ipip",
			deleteRuleExpected: "-d -t 10.131.153.125:8080 -r 10.131.153.76:8080",
		},
	}

	for _, test := range tests {
		deleteRule := ipvsManager.createDeleteRuleFromAddRule(test.addRule)
		if deleteRule != test.deleteRuleExpected {
			t.Fatal("invalid delete rule produced from add rule:", deleteRule, " -- expected", test.deleteRuleExpected)
		}
	}
}

// TestIPVSMerge tests the merging of generated and existing rules into a simplest-form ipvsadm ruleset
func TestIPVSMerge(t *testing.T) {

	ipvsConfigured := []string{
		"-A -t 10.131.153.120:71 -s wrr",
		"-a -t 10.131.153.120:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.120:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.120:8889 -s mh",
		"-a -t 10.131.153.120:8889 -r 10.131.153.75:8889 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.120:8889 -r 10.131.153.76:8889 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.120:8889 -r 10.131.153.77:8889 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.120:8889 -r 10.131.153.78:8889 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.120:8889 -r 10.131.153.79:8889 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.120:8889 -r 10.131.153.81:8889 -i -w 0 --tun-type ipip",
		"-A -t 10.131.153.121:71 -s wrr",
		"-a -t 10.131.153.121:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.121:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.122:71 -s wrr",
		"-a -t 10.131.153.122:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.122:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.122:80 -s mh",
		"-a -t 10.131.153.122:80 -r 10.131.153.75:80 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.122:80 -r 10.131.153.76:80 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:80 -r 10.131.153.77:80 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:80 -r 10.131.153.78:80 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:80 -r 10.131.153.79:80 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:80 -r 10.131.153.81:80 -i -w 0 --tun-type ipip",
		"-A -t 10.131.153.122:8081 -s wrr",
		"-a -t 10.131.153.122:8081 -r 10.131.153.75:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:8081 -r 10.131.153.76:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:8081 -r 10.131.153.77:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:8081 -r 10.131.153.78:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:8081 -r 10.131.153.79:8081 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.122:8081 -r 10.131.153.81:8081 -i -w 0 --tun-type ipip",
		"-A -t 10.131.153.123:71 -s wrr",
		"-a -t 10.131.153.123:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.123:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.123:8080 -s mh -b mh-fallback,mh-port",
		"-a -t 10.131.153.123:8080 -r 10.131.153.75:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.123:8080 -r 10.131.153.76:8080 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.123:8080 -r 10.131.153.77:8080 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.123:8080 -r 10.131.153.78:8080 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.123:8080 -r 10.131.153.79:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.123:8080 -r 10.131.153.81:8080 -i -w 0 --tun-type ipip",
		"-A -t 10.131.153.124:71 -s wrr",
		"-a -t 10.131.153.124:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.124:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.124:8080 -s mh",
		"-a -t 10.131.153.124:8080 -r 10.131.153.75:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.124:8080 -r 10.131.153.76:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.124:8080 -r 10.131.153.77:8080 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.124:8080 -r 10.131.153.78:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.124:8080 -r 10.131.153.79:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.124:8080 -r 10.131.153.81:8080 -i -w 1 --tun-type ipip",
		"-A -t 10.131.153.125:71 -s wrr",
		"-a -t 10.131.153.125:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.125:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.125:8080 -s mh -b mh-fallback,mh-port",
		"-a -t 10.131.153.125:8080 -r 10.131.153.75:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8080 -r 10.131.153.76:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8080 -r 10.131.153.77:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8080 -r 10.131.153.78:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8080 -r 10.131.153.79:8080 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.125:8080 -r 10.131.153.81:8080 -i -w 0 --tun-type ipip",
		"-A -t 10.131.153.125:8081 -s wrr",
		"-a -t 10.131.153.125:8081 -r 10.131.153.75:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8081 -r 10.131.153.76:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8081 -r 10.131.153.77:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8081 -r 10.131.153.78:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8081 -r 10.131.153.79:8081 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.125:8081 -r 10.131.153.81:8081 -i -w 0 --tun-type ipip",
	}

	generatedRules := []string{
		"-A -t 10.131.153.120:71 -s wrr",
		"-a -t 10.131.153.120:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.120:8889 -s mh -b flag-1,flag-2",
		"-a -t 10.131.153.120:8889 -r 10.131.153.75:8889 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:8889 -r 10.131.153.76:8889 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:8889 -r 10.131.153.77:8889 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.120:8889 -r 10.131.153.78:8889 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.120:8889 -r 10.131.153.79:8889 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:8889 -r 10.131.153.81:8889 -i -w 0 -x 0 -y 0",
		"-A -t 10.131.153.121:71 -s wrr",
		"-a -t 10.131.153.121:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.122:71 -s wrr",
		"-a -t 10.131.153.122:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.122:80 -s mh -b flag-1,flag-2",
		"-a -t 10.131.153.122:80 -r 10.131.153.75:80 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.122:80 -r 10.131.153.76:80 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:80 -r 10.131.153.77:80 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:80 -r 10.131.153.78:80 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:80 -r 10.131.153.79:80 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:80 -r 10.131.153.81:80 -i -w 0 -x 0 -y 0",
		"-A -t 10.131.153.122:8081 -s wrr",
		"-a -t 10.131.153.122:8081 -r 10.131.153.75:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:8081 -r 10.131.153.76:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:8081 -r 10.131.153.77:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:8081 -r 10.131.153.78:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:8081 -r 10.131.153.79:8081 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.122:8081 -r 10.131.153.81:8081 -i -w 0 -x 0 -y 0",
		"-A -t 10.131.153.123:71 -s wrr",
		"-a -t 10.131.153.123:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.123:8080 -s mh -b flag-1,flag-2",
		"-a -t 10.131.153.123:8080 -r 10.131.153.75:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:8080 -r 10.131.153.76:8080 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.123:8080 -r 10.131.153.77:8080 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.123:8080 -r 10.131.153.78:8080 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.123:8080 -r 10.131.153.79:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:8080 -r 10.131.153.81:8080 -i -w 0 -x 0 -y 0",
		"-A -t 10.131.153.124:71 -s wrr",
		"-a -t 10.131.153.124:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.124:8080 -s mh -b flag-1,flag-2",
		"-a -t 10.131.153.124:8080 -r 10.131.153.75:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:8080 -r 10.131.153.76:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:8080 -r 10.131.153.77:8080 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.124:8080 -r 10.131.153.78:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:8080 -r 10.131.153.79:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:8080 -r 10.131.153.81:8080 -i -w 1 -x 0 -y 0",
		"-A -t 10.131.153.125:71 -s wrr",
		"-a -t 10.131.153.125:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.125:8080 -s mh -b flag-1,flag-2",
		"-a -t 10.131.153.125:8080 -r 10.131.153.75:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8080 -r 10.131.153.76:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8080 -r 10.131.153.77:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8080 -r 10.131.153.78:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8080 -r 10.131.153.79:8080 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.125:8080 -r 10.131.153.81:8080 -i -w 0 -x 0 -y 0",
		"-A -t 10.131.153.125:8081 -s wrr",
		"-a -t 10.131.153.125:8081 -r 10.131.153.75:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8081 -r 10.131.153.76:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8081 -r 10.131.153.77:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8081 -r 10.131.153.78:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8081 -r 10.131.153.79:8081 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.125:8081 -r 10.131.153.81:8081 -i -w 0 -x 0 -y 0",
	}

	ipvsManager := IPVS{
		logger: logrus.New(),
	}
	rules := ipvsManager.merge(ipvsConfigured, generatedRules)
	t.Log("Final rules:")
	for _, r := range rules {
		t.Log("ipvsadm " + r)
	}

}

// TestIPVSEquality tests with actual sample input from a server to be sure it evaluates rules correctly
func TestIPVSEquality(t *testing.T) {

	ipvsManager := IPVS{
		logger: logrus.New(),
	}

	ipvsConfigured := []string{
		"-A -t 10.131.153.120:71 -s wrr",
		"-a -t 10.131.153.120:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.120:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.120:8889 -s mh -b mh-fallback,mh-port",
		"-a -t 10.131.153.120:8889 -r 10.131.153.75:8889 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.120:8889 -r 10.131.153.76:8889 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.120:8889 -r 10.131.153.77:8889 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.120:8889 -r 10.131.153.78:8889 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.120:8889 -r 10.131.153.79:8889 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.120:8889 -r 10.131.153.81:8889 -i -w 0 --tun-type ipip",
		"-A -t 10.131.153.121:71 -s wrr",
		"-a -t 10.131.153.121:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.121:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.122:71 -s wrr",
		"-a -t 10.131.153.122:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.122:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.122:80 -s mh -b mh-fallback,mh-port",
		"-a -t 10.131.153.122:80 -r 10.131.153.75:80 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.122:80 -r 10.131.153.76:80 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:80 -r 10.131.153.77:80 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:80 -r 10.131.153.78:80 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:80 -r 10.131.153.79:80 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:80 -r 10.131.153.81:80 -i -w 0 --tun-type ipip",
		"-A -t 10.131.153.122:8081 -s wrr",
		"-a -t 10.131.153.122:8081 -r 10.131.153.75:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:8081 -r 10.131.153.76:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:8081 -r 10.131.153.77:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:8081 -r 10.131.153.78:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.122:8081 -r 10.131.153.79:8081 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.122:8081 -r 10.131.153.81:8081 -i -w 0 --tun-type ipip",
		"-A -t 10.131.153.123:71 -s wrr",
		"-a -t 10.131.153.123:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.123:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.123:8080 -s mh -b mh-fallback,mh-port",
		"-a -t 10.131.153.123:8080 -r 10.131.153.75:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.123:8080 -r 10.131.153.76:8080 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.123:8080 -r 10.131.153.77:8080 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.123:8080 -r 10.131.153.78:8080 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.123:8080 -r 10.131.153.79:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.123:8080 -r 10.131.153.81:8080 -i -w 0 --tun-type ipip",
		"-A -t 10.131.153.124:71 -s wrr",
		"-a -t 10.131.153.124:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.124:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.124:8080 -s mh -b mh-fallback,mh-port",
		"-a -t 10.131.153.124:8080 -r 10.131.153.75:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.124:8080 -r 10.131.153.76:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.124:8080 -r 10.131.153.77:8080 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.124:8080 -r 10.131.153.78:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.124:8080 -r 10.131.153.79:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.124:8080 -r 10.131.153.81:8080 -i -w 1 --tun-type ipip",
		"-A -t 10.131.153.125:71 -s wrr",
		"-a -t 10.131.153.125:71 -r 10.131.153.75:71 -g -w 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.76:71 -g -w 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.77:71 -g -w 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.78:71 -g -w 1",
		"-a -t 10.131.153.125:71 -r 10.131.153.79:71 -g -w 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.81:71 -g -w 0",
		"-A -t 10.131.153.125:8080 -s mh -b mh-fallback,mh-port",
		"-a -t 10.131.153.125:8080 -r 10.131.153.75:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8080 -r 10.131.153.76:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8080 -r 10.131.153.77:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8080 -r 10.131.153.78:8080 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8080 -r 10.131.153.79:8080 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.125:8080 -r 10.131.153.81:8080 -i -w 0 --tun-type ipip",
		"-A -t 10.131.153.125:8081 -s wrr",
		"-a -t 10.131.153.125:8081 -r 10.131.153.75:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8081 -r 10.131.153.76:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8081 -r 10.131.153.77:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8081 -r 10.131.153.78:8081 -i -w 0 --tun-type ipip",
		"-a -t 10.131.153.125:8081 -r 10.131.153.79:8081 -i -w 1 --tun-type ipip",
		"-a -t 10.131.153.125:8081 -r 10.131.153.81:8081 -i -w 0 --tun-type ipip",
	}

	ipvsGenerated := []string{
		"-A -t 10.131.153.120:71 -s wrr",
		"-a -t 10.131.153.120:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.120:8889 -s mh -b flag-1,flag-2",
		"-a -t 10.131.153.120:8889 -r 10.131.153.75:8889 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:8889 -r 10.131.153.76:8889 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:8889 -r 10.131.153.77:8889 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:8889 -r 10.131.153.78:8889 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.120:8889 -r 10.131.153.79:8889 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.120:8889 -r 10.131.153.81:8889 -i -w 0 -x 0 -y 0",
		"-A -t 10.131.153.121:71 -s wrr",
		"-a -t 10.131.153.121:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.121:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.122:71 -s wrr",
		"-a -t 10.131.153.122:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.122:80 -s mh -b flag-1,flag-2",
		"-a -t 10.131.153.122:80 -r 10.131.153.75:80 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.122:80 -r 10.131.153.76:80 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:80 -r 10.131.153.77:80 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:80 -r 10.131.153.78:80 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:80 -r 10.131.153.79:80 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:80 -r 10.131.153.81:80 -i -w 0 -x 0 -y 0",
		"-A -t 10.131.153.122:8081 -s wrr",
		"-a -t 10.131.153.122:8081 -r 10.131.153.75:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:8081 -r 10.131.153.76:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:8081 -r 10.131.153.77:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:8081 -r 10.131.153.78:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.122:8081 -r 10.131.153.79:8081 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.122:8081 -r 10.131.153.81:8081 -i -w 0 -x 0 -y 0",
		"-A -t 10.131.153.123:71 -s wrr",
		"-a -t 10.131.153.123:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.123:8080 -s mh -b flag-1,flag-2",
		"-a -t 10.131.153.123:8080 -r 10.131.153.75:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:8080 -r 10.131.153.76:8080 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.123:8080 -r 10.131.153.77:8080 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.123:8080 -r 10.131.153.78:8080 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.123:8080 -r 10.131.153.79:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.123:8080 -r 10.131.153.81:8080 -i -w 0 -x 0 -y 0",
		"-A -t 10.131.153.124:71 -s wrr",
		"-a -t 10.131.153.124:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.124:8080 -s mh -b flag-1,flag-2",
		"-a -t 10.131.153.124:8080 -r 10.131.153.75:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:8080 -r 10.131.153.76:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:8080 -r 10.131.153.77:8080 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.124:8080 -r 10.131.153.78:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:8080 -r 10.131.153.79:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.124:8080 -r 10.131.153.81:8080 -i -w 1 -x 0 -y 0",
		"-A -t 10.131.153.125:71 -s wrr",
		"-a -t 10.131.153.125:71 -r 10.131.153.75:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.76:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.77:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.78:71 -g -w 1 -x 0 -y 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.79:71 -g -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:71 -r 10.131.153.81:71 -g -w 0 -x 0 -y 0",
		"-A -t 10.131.153.125:8080 -s mh -b flag-1,flag-2",
		"-a -t 10.131.153.125:8080 -r 10.131.153.75:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8080 -r 10.131.153.76:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8080 -r 10.131.153.77:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8080 -r 10.131.153.78:8080 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8080 -r 10.131.153.79:8080 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.125:8080 -r 10.131.153.81:8080 -i -w 0 -x 0 -y 0",
		"-A -t 10.131.153.125:8081 -s wrr",
		"-a -t 10.131.153.125:8081 -r 10.131.153.75:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8081 -r 10.131.153.76:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8081 -r 10.131.153.77:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8081 -r 10.131.153.78:8081 -i -w 0 -x 0 -y 0",
		"-a -t 10.131.153.125:8081 -r 10.131.153.79:8081 -i -w 1 -x 0 -y 0",
		"-a -t 10.131.153.125:8081 -r 10.131.153.81:8081 -i -w 0 -x 0 -y 0",
	}

	equal := ipvsManager.ipvsEquality(ipvsConfigured, ipvsGenerated)
	t.Log("Equality:", equal)

}
