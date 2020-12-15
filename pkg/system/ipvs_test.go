package system

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Comcast/Ravel/pkg/types"
)

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

	instance := &ipvs{}
	out := instance.merge(configured, generated)
	for i, rule := range out {
		if rule != expects[i] {
			t.Fatalf("expected rule to match at index %d. %s!=%s", i, rule, expects[i])
		}
	}
}

func TestGetNodeWeightsAndLimits(t *testing.T) {
	// generate a list of 3 nodes
	nodes := []types.Node{
		types.Node{Addresses: []string{"10.11.12.13"}},
		types.Node{Addresses: []string{"10.11.12.14"}},
		types.Node{Addresses: []string{"10.11.12.15"}},
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

	for _, test := range tests {
		sc := &types.ServiceDef{
			IPVSOptions: test.i,
		}
		out := getNodeWeightsAndLimits(nodes, sc, false, 0)
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
