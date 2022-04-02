package iptables

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/Comcast/Ravel/pkg/stats"
	"github.com/Comcast/Ravel/pkg/types"
	"github.com/Comcast/Ravel/pkg/watcher"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

func getTestJSON(fileDesc string) ([]byte, error) {
	return ioutil.ReadFile(fileDesc)
}

func TestCIDRMasq(t *testing.T) {
	b, err := getTestJSON("./endpoint_test_data.json")
	if err != nil {
		t.Fatal(err)
	}

	l := &logrus.Logger{}
	// emulate defaults; bgp kind, empty config-key, ravel chain
	ipTables, err := NewIPTables(context.Background(), stats.KindBGP, "", "1.2.3.4", "RAVEL", true, l)
	if err != nil {
		t.Fatal(err)
	}

	n := &v1.Node{}
	err = json.Unmarshal(b, &n)
	if err != nil {
		t.Fatal(err)
	}

	b, err = getTestJSON("./configmap_test_data.json")
	if err != nil {
		t.Fatal(err)
	}

	c := &types.ClusterConfig{}
	err = json.Unmarshal(b, &c) // should we actually use the constructors?
	if err != nil {
		t.Fatal(err)
	}

	w := &watcher.Watcher{}

	rules, err := ipTables.GenerateRulesForNode(w, n.Name, c, true)
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range rules {
		for _, rules := range v.Rules {
			// fmt.Printf("Chainrule: %s ruleName %s rule: %s\n", k, v.ChainRule, rules)
			fmt.Printf("%s\n", rules)
		}
	}
}

func TestWeightEndpoints(t *testing.T) {
	b, err := getTestJSON("./endpoint_test_data.json")
	if err != nil {
		t.Fatal(err)
	}

	l := &logrus.Logger{}
	// emulate defaults; bgp kind, empty config-key, ravel chain
	ipTables, err := NewIPTables(context.Background(), stats.KindBGP, "", "", "RAVEL", true, l)
	if err != nil {
		t.Fatal(err)
	}

	n := &v1.Node{}
	err = json.Unmarshal(b, &n)
	if err != nil {
		t.Fatal(err)
	}

	b, err = getTestJSON("./configmap_test_data.json")
	if err != nil {
		t.Fatal(err)
	}

	c := &types.ClusterConfig{}
	err = json.Unmarshal(b, &c) // should we actually use the constructors?
	if err != nil {
		t.Fatal(err)
	}

	w := &watcher.Watcher{}

	rules, err := ipTables.GenerateRulesForNode(w, n.Name, c, true)
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range rules {
		for _, rules := range v.Rules {
			// fmt.Printf("Chainrule: %s ruleName %s rule: %s\n", k, v.ChainRule, rules)
			fmt.Printf("%s\n", rules)
		}
	}
}

func TestComputeProbability(t *testing.T) {
	probabilities := []string{
		"0.20000000000",
		"0.25000000000",
		"0.33333333333",
		"0.50000000000",
		"1.00000000000",
	}

	numEndpoints := len(probabilities)
	// 5 backends
	for i := 0; i < 4; i++ {
		p := computeEndpointProbability(numEndpoints - i)
		fmt.Println("P:", p)
		if p != probabilities[i] {
			t.Fatal(fmt.Sprintf("probabilities did not match for backend. expected: %s got: %s", probabilities[i], p))
		}
	}
}

// func TestGenerateRules(t *testing.T) {
// 	cc := _getCCForTest()
// 	i := &iptables{}
//
// 	r, err := i.GenerateRules(cc)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	if len(r) != 3 {
// 		t.Fatalf("expected three chains. saw %d", len(r))
// 	}
//
// 	if len(r[BaseChainName].Rules) != 8 {
// 		t.Fatalf("expected 8 rules. saw %d", len(r[BaseChainName].Rules))
// 	}
//
// 	b, _ := json.MarshalIndent(r, " ", " ")
// 	fmt.Println(string(b))
//
// }

func _getCCForTest() *types.ClusterConfig {
	c := `
            {
              "vipPool": [
                "172.27.223.81",
                "172.27.223.89"
              ],
              "labels": {
                "vlan-786": "true"
              },
              "config": {
                "172.27.223.81": {
                  "80": {
                    "namespace": "test-namespace",
                    "service": "test-service",
                    "portName": "http"
                  },
                  "8080": {
                    "namespace": "test-namespace",
                    "service": "test-service",
                    "portName": "port-not-found"
                  }
                },
                "172.27.223.89": {
                  "90": {
                    "namespace": "test-namespace",
                    "service": "service-not-found",
                    "portName": "http"
                  },
                  "9999": {
                    "namespace": "test-namespace",
                    "service": "test-service",
                    "portName": "http"
                  }
                }
              }
            }
        `
	out := &types.ClusterConfig{}
	_ = json.Unmarshal([]byte(c), out)
	return out
}
