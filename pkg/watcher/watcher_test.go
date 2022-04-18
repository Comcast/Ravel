package watcher

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	log "github.com/sirupsen/logrus"
)

func loadTestWatcherJSON(filePath string) (*Watcher, error) {
	var w Watcher
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, &w)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func TestServiceInEndpoints(t *testing.T) {
	w, err := loadTestWatcherJSON("watcher.json")
	if err != nil {
		t.Fatal(err)
	}
	if !w.ServiceIsConfigured("vsg-ml-inference-consumer", "nginx") {
		t.Fatal("service not configured when it should be")
	}

	if !w.userServiceInEndpoints("nginx", "vsg-ml-inference-consumer", "http") {
		t.Fatal("service not found in endpoints when it should be")
	}

	if !w.ServiceHasValidEndpoints("nginx", "vsg-ml-inference-consumer") {
		t.Fatal("service has not valid endpoints when it should")
	}

}

func TestBuildClusterConfig(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	w, err := loadTestWatcherJSON("watcher.json")
	if err != nil {
		t.Fatal(err)
	}
	cc, err := w.buildClusterConfig()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(len(cc.Config))
}
