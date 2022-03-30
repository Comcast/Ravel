package system

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/Comcast/Ravel/pkg/types"
	"github.com/Comcast/Ravel/pkg/watcher"
)

func TestHasChanged(t *testing.T) {

	// load a config json from disk
	b, err := ioutil.ReadFile("clusterconfig.json")
	if err != nil {
		t.Fatal("failed to read clusterconfig.json:", err)
	}

	// load a sample config into a var
	var clusterConfig *types.ClusterConfig
	err = json.Unmarshal(b, &clusterConfig)
	if err != nil {
		t.Fatal("failed to unmarshal clusterconfig.json:", err)
	}

	// load a sample config into a var again, but representing a new cluster
	var newClusterConfig *types.ClusterConfig
	err = json.Unmarshal(b, &newClusterConfig)
	if err != nil {
		t.Fatal("failed to unmarshal clusterconfig.json:", err)
	}

	// make a modification to the new config that should be ignored
	newClusterConfig.Config["10.131.153.121"]["70"].IPVSOptions.Flags = "asdf"

	// have the watcher check if our configs are different or not
	watcher := watcher.Watcher{}
	hasChanged := watcher.HasConfigChanged(clusterConfig, newClusterConfig)

	if hasChanged {
		t.Fatal("The config has not changed, but did show that it had changed")
	}
	t.Log("the config correctly reflected that it has not changed")
}

/*
func TestIgnoreMissingServices(t *testing.T) {
	logger := logrus.New()
	logger.EnableSilent()

	w := &watcher{
		logger: logger,
	}
	services := _getServicesForTest()
	inCC := _getCCForTest()

	newCC, err := w.ignoreMissingServices(services, inCC)
	if err != nil {
		t.Fatal(err)
	}

	// we wxpect: 172.27.223.81:8080 to be not found, 172.27.223.81:80 to be found
	// we expect: 172.27.223.89:8080 to be not found, 172.27.223.89:80 to be found
	tests := []struct {
		vip   string
		port  string
		found bool
	}{
		{"172.27.223.81", "80", true},
		{"172.27.223.89", "9999", true},
		{"172.27.223.81", "8080", false},
		{"172.27.223.89", "90", false},
	}
	for _, test := range tests {
		if _, found := newCC.Config[types.ServiceIP(test.vip)]; found != true {
			t.Fatalf("expected vip '%s' to be present in clusterconfig", test.vip)
		}
		if _, found := newCC.Config[types.ServiceIP(test.vip)][test.port]; found != test.found {
			t.Errorf("expected %s:%s to be found=%v. found=%v", test.vip, test.port, test.found, found)
		}
	}
}

func TestExtractConfigKey(t *testing.T) {
	var err error
	var w *watcher

	w = &watcher{configKey: "green"}
	_, err = w.extractConfigKey(_testCC())
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	w = &watcher{configKey: "black"}
	_, err = w.extractConfigKey(_testCC())
	if err == nil {
		t.Errorf("expected error for invalid config key. saw nil")
	}

	w = &watcher{configKey: "invalid"}
	_, err = w.extractConfigKey(_testCC())
	if err == nil {
		t.Errorf("expected error for invalid config json. saw nil")
	} else if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("expected unmarshal error. saw %v", err)
	}

	w = &watcher{configKey: "nil"}
	_, err = w.extractConfigKey(_testCC())
	if err == nil {
		t.Errorf("expected error for nil config.Config. saw nil")
	} else if err.Error() != "config is nil" {
		t.Errorf("expected nil config error. saw %v", err)
	}

}

func _testCC() *v1.ConfigMap {
	c := `
            {
              "kind": "ConfigMap",
              "apiVersion": "v1",
              "metadata": {
                "name": "kube2ipvs",
                "namespace": "platform-load-balancer"
              },
              "data": {
                "green": "{\"config\":{}}",
                "invalid": "{this is invalid}",
                "nil": "{}"
              }
            }
        `
	out := &v1.ConfigMap{}
	_ = json.Unmarshal([]byte(c), out)
	return out
}

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

func _getServicesForTest() *v1.ServiceList {
	s := `
            {
              "kind": "ServiceList",
              "apiVersion": "v1",
              "metadata": {},
              "items": [
                {
                  "metadata": {
                    "name": "test-service",
                    "namespace": "test-namespace"
                  },
                  "spec": {
                    "ports": [
                      {
                        "name": "http",
                        "protocol": "TCP",
                        "port": 9292,
                        "targetPort": 9292,
                        "nodePort": 9637
                      },
                      {
                        "name": "data",
                        "protocol": "TCP",
                        "port": 9393,
                        "targetPort": 9393,
                        "nodePort": 9474
                      }
                    ],
                    "selector": {
                      "app": "packager"
                    },
                    "clusterIP": "192.168.1.92",
                    "type": "NodePort",
                    "sessionAffinity": "None"
                  },
                  "status": {
                    "loadBalancer": {}
                  }
                }
              ]
            }
        `
	out := &v1.ServiceList{}
	_ = json.Unmarshal([]byte(s), out)
	return out
}


*/
