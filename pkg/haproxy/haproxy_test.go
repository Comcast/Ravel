package haproxy

import (
	"context"
	"testing"

	"github.com/Sirupsen/logrus"
)

func TestRender(t *testing.T) {
	// this isn't a super-traditional test, but it allows me to easily see
	// what template is rendered to disk which makes verifying changes to
	// the template easy
	_, err := NewHAProxy(context.Background(),
		"/usr/local/bin/haproxy",
		"/etc/ravel/",
		"2001:1234:10ad:ba1a::1",
		[]string{"192.168.12.12", "192.168.12.13", "192.168.12.14"},
		"8123",
		"8080",
		make(chan HAProxyError),
		logrus.New(),
	)

	if err != nil {
		t.Fatalf("could not start proxy manager: %+v", err)
	}
}
