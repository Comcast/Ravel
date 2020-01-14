package types

import (
	"fmt"
	"testing"

	"k8s.io/api/core/v1"
)

func TestConfigDataConvert(t *testing.T) {
	data := map[string]string{"green": `{
                "labels": {"vlan-786": "true", "vlan": "786"},
                "config": {
                    "10.54.213.165":{
                        "80":{"namespace": "syseng", "service": "mod-super8", "portName": "http"},
                        "81":{"namespace": "statsd-demo", "service": "ui", "portName": "http"}
                    }
                }
        }`}
	config := &v1.ConfigMap{Data: data}

	clusterConfig, err := NewClusterConfig(config, "green")
	if err != nil {
		t.Errorf("Error getting new config: %s", err.Error())
	}

	fmt.Printf("clusterConfig: %v", clusterConfig)
}
