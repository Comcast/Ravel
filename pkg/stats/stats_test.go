package stats

import (
	"fmt"
	"strings"
	"testing"
)

func TestCounters(t *testing.T) {
	c := &counters{}

	if c.TCP.Rx != 0 {
		t.Fatal("expected rx to be zero for initialized object")
	}
	c.AddTCPRx(65535)
	if c.TCP.Rx != 65535 {
		t.Fatalf("expected tcp.rx to equal 65535. saw %d", c.TCP.Rx)
	}
	c.AddTCPRx(65535)
	if c.TCP.Rx != 65535*2 {
		t.Fatalf("expected tcp.rx to equal 131070. saw %d", c.TCP.Rx)
	}
}

func TestSetBPFFilter(t *testing.T) {
	ips := []string{"1.2.3.4", "2.3.4.5"}
	filters := strings.Join(ips, " or ")
	fmt.Println(filters)
}

// doing nothing takes .29ns/op
// mutex lock/unlock takes 5.4ns/op
// atomic addition takes 5.4ns/op
// channel writes take around 75ns/op
// creating a new struct instance takes around 25ns/op
func BenchmarkCounters(b *testing.B) {
	for n := 0; n < b.N; n++ {
		c := &counters{}
		c.AddTCPRx(1) // without the fn call this only takes 2ns
	}
}
