package haproxy

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
)

func returnNewHAProxy() (*HAProxyManager, error) {
	return NewHAProxy(context.Background(),
		"/usr/local/bin/haproxy",
		"/etc/ravel/",
		"2001:1234:10ad:ba1a::1",
		"8123",
		[]string{"192.168.12.12", "192.168.12.13", "192.168.12.14"},
		"8080",
		"50312",
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

func TestGetPID(t *testing.T) {
	// out of "ps aux" from a runnning realserver
	// pid and path defined in this
	testBytes := []byte(`
	PID   USER     TIME  COMMAND
    1 root      0:00 /usr/lib/systemd/systemd --default-standard-output=tty --log-target=null --show-status=0
    3 root      0:00 /usr/lib/systemd/systemd-journald
    6 root      0:25 /bin/ravel realserver --nodename=10.54.213.138 --auto-configure-service=rdei-system/unicorns-gre
  812 root      0:00 sh
  826 root      0:00 sh
  850 haproxy   0:25 haproxy -f /etc/ravel/2001:558:1044:1f3:10ad:ba1a:a36:d593-8080.conf -p /var/run/haproxy.pid -sf
 1618 root      0:00 ps aux
`)

	h := HAProxyManager{
		configDir:   "/etc/ravel",
		listenAddr:  "2001:558:1044:1f3:10ad:ba1a:a36:d593",
		servicePort: "8080",
	}

	pid := h.fetchPIDFromOutput(testBytes)

	if pid != "850" {
		t.Fatalf("did not find appropriate pid: expected %s, saw %s", "850", pid)
	}
}
