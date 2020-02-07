package haproxy

import (
	"context"
	"testing"

	"github.com/Sirupsen/logrus"
)

func returnNewHAProxy() (*HAProxyManager, error) {
	return NewHAProxy(context.Background(),
		"/usr/local/bin/haproxy",
		"/etc/ravel/",
		"2001:1234:10ad:ba1a::1",
		[]string{"192.168.12.12", "192.168.12.13", "192.168.12.14"},
		"8123",
		"8080",
		make(chan HAProxyError),
		logrus.New())
}

func TestRender(t *testing.T) {
	// this isn't a super-traditional test, but it allows me to easily see
	// what template is rendered to disk which makes verifying changes to
	// the template easy
	// run with sudo, btw
	_, err := returnNewHAProxy()

	if err != nil {
		t.Fatalf("could not start proxy manager: %+v", err)
	}
}

func TestGetRemovals(t *testing.T) {
	h := HAProxySetManager{
		sources: map[string]HAProxy{
			"2001:1eaf:bead:10ad:ba1a::1:8080": &HAProxyManager{
				listenAddr: "2001:1eaf:bead:10ad:ba1a::1",
			},
			"2001:1eaf:bead:10ad:ba1a::2:8080": &HAProxyManager{
				listenAddr: "2001:1eaf:bead:10ad:ba1a::2",
			},
			"2001:1eaf:bead:10ad:ba1a::1:8081": &HAProxyManager{
				listenAddr: "2001:1eaf:bead:10ad:ba1a::3",
			},
		},
	}

	rem := h.GetRemovals([]string{"2001:1eaf:bead:10ad:ba1a::1:8080", "2001:1eaf:bead:10ad:ba1a::2:8080"})
	if len(rem) == 0 {
		t.Fatalf("failed to collect any removals")
	}

	if rem[0] != "2001:1eaf:bead:10ad:ba1a::1:8081" {
		t.Fatalf("failed to collect appropriate removal: expected %s, saw %s", "2001:1eaf:bead:10ad:ba1a::1:8081", rem[0])
	}
}
