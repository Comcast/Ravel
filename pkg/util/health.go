package util

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
)

// listens on a port and returns a set of information about the health of the system
func ListenForHealth(primaryInterface string, port int, logger logrus.FieldLogger) {
	logger.Infof("initializing /health handler on port %d", port)

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		start := time.Now()
		defer func() {
			logger.Info("request completed in %v", time.Now().Sub(start))
		}()
		data := health(primaryInterface, logger)
		b, _ := json.MarshalIndent(data, " ", " ")
		w.Write(b)
	})

	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		logger.Error("running without health checks")
	}
}

type healthData struct {
	Mode      string
	IPTables  []string            `json:"iptables,omitempty"`
	Interface map[string][]string `json:"interface,omitempty"`
	IPVS      []string            `json:"ipvs,omitempty"`

	Errors []string `json:"errors,omitempty"`
}

func health(primaryInterface string, logger logrus.FieldLogger) *healthData {
	h := &healthData{
		Mode:      "unknown",
		Interface: map[string][]string{},
		Errors:    []string{},
	}

	// what are the ipvsadm rules?
	out, err := exec.Command("ipvsadm").Output()
	if err != nil {
		h.Errors = append(h.Errors, err.Error())
	}
	h.IPVS = strings.Split(string(out), "\n")

	// what are the iptables rules?
	out, err = exec.Command("iptables", "-w", "-t", "nat", "-S", "RDEI-LB").Output()
	if err != nil {
		h.Errors = append(h.Errors, err.Error())
	}
	h.IPTables = strings.Split(string(out), "\n")

	// what are the interface rules
	for _, iface := range []string{"lo", primaryInterface} {
		out, err = exec.Command("ip", "addr", "show", "dev", iface).Output()
		if err != nil {
			h.Errors = append(h.Errors, err.Error())
		}
		h.Interface[iface] = strings.Split(string(out), "\n")
	}

	return h
}
