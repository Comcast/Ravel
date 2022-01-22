package system

import (
	"context"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestDiffAddressSets(t *testing.T) {
	have := []string{"one", "two", "three"}
	want := []string{"two", "three", "four"}

	instance := &ipManager{}
	remove, add := instance.Compare(have, want, false)
	if !reflect.DeepEqual(add, []string{"four"}) {
		t.Fatalf("expected 'four' to be added. saw %v", add)
	}
	if !reflect.DeepEqual(remove, []string{"one"}) {
		t.Fatalf("expected 'one' to be removed. saw %v", remove)
	}
}

func TestGetDummyInterfaces(t *testing.T) {
	if os.Getenv("TEST_OS") != "mac" {
		t.Skip("This test only works with a faked 'ip' command script")
	}
	// make a new ip manager
	ipManager, err := NewIP(context.Background(), "enp6s0", "172.26.223.1", 55, 0, logrus.New())
	if err != nil {
		t.Fatal(err)
	}

	// use the faked binary bash script in this directory
	ipManager.IPCommandPath = "./ip"

	ifaces, err := ipManager.retrieveDummyIFaces()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ifaces)
}

func TestParseInterfacesFromGrep(t *testing.T) {
	output := `14: 100_95_39_163: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
	link/ether 5a:cf:00:e5:7c:d0 brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 0 maxmtu 0 
	dummy addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 
    15: ravel_315f325f3: <BROADCAST,NOARP,UP,LOWER_UP> mtu 9000 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
	link/ether 56:39:16:d6:c2:25 brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 0 maxmtu 0 
	dummy addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 
    16: ravel_315c125f3: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
	link/ether 72:fe:53:93:33:0b brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 0 maxmtu 0 
	dummy addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 
    17: ravel_312f32ffa: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
	link/ether 9e:f9:5e:d8:2a:7c brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 0 maxmtu 0 
	dummy addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 
    18: ravel_315f435f3: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
	link/ether 72:aa:12:53:aa:09 brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 0 maxmtu 0 
	dummy addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 
    19: ravel_612a325f3: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
	link/ether b2:12:33:78:ad:79 brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 0 maxmtu 0 
	dummy addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 
    20: anotheradapter: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
	link/ether 86:aa:46:61:62:4e brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 0 maxmtu 0 
	dummy addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 
    --
    13390: nodelocaldns: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default 
	link/ether 52:91:0c:a6:ba:86 brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 0 maxmtu 0 
	dummy addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535`

	iFaces := parseInterfacesFromGrep(output)
	interfaceCount := len(iFaces)
	if interfaceCount != 5 {
		t.Error("expected to find 9 ravel_ interfaces, but found ", strconv.Itoa(interfaceCount))
	}

	// we should never select the `nodelocaldns` interface for any reason
	for _, i := range iFaces {
		if i == "nodelocaldns" {
			t.Error("found nodelocaldns adapter, but should not have")
		}
	}

	t.Log(iFaces)
}

func TestGenerateDeviceLabel(t *testing.T) {
	i := ipManager{}
	name := i.generateDeviceLabel("1.2.3.4", false)
	t.Log("generated name:", name)
	if len(name) != 15 {
		t.Error("generated dummy adapter name was not 15 characters")
	}
}

func TestParseAddressData(t *testing.T) {
	data := `
2: enp6s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:25:b5:36:0a:4f brd ff:ff:ff:ff:ff:ff
    inet 172.27.223.123/24 brd 172.27.223.255 scope global dynamic enp6s0
       valid_lft 76859sec preferred_lft 76859sec
    inet 172.27.223.83/32 scope global enp6s0
       valid_lft forever preferred_lft forever
    inet 172.27.223.84/32 scope global enp6s0
       valid_lft forever preferred_lft forever
    inet 172.27.223.85/32 scope global enp6s0
       valid_lft forever preferred_lft forever
    inet 172.27.223.87/32 scope global enp6s0
       valid_lft forever preferred_lft forever
    inet 172.27.223.88/32 scope global enp6s0:k2i
       valid_lft forever preferred_lft forever
    inet 172.27.223.82/32 scope global enp6s0
       valid_lft forever preferred_lft forever
    inet 172.27.223.86/32 scope global enp6s0
       valid_lft forever preferred_lft forever
    inet 172.27.223.89/32 scope global enp6s0
       valid_lft forever preferred_lft forever
    inet 172.27.223.81/32 scope global enp6s0:k2i
       valid_lft forever preferred_lft forever
    inet6 2001:558:1044:159:225:b5ff:fe36:a4f/64 scope global mngtmpaddr noprefixroute dynamic
       valid_lft 2280062sec preferred_lft 292862sec
    inet6 2001:558:1044:15a:225:b5ff:fe36:a4f/64 scope global mngtmpaddr noprefixroute dynamic
       valid_lft 2280062sec preferred_lft 292862sec
    inet6 2001:558:1044:15b:225:b5ff:fe36:a4f/64 scope global mngtmpaddr noprefixroute dynamic
       valid_lft 2280062sec preferred_lft 292862sec
    `

	// make a new ip manager
	// ERIC: what is the 'announce' int and what is the 'ignore' int here?
	ipManager, err := NewIP(context.Background(), "enp6s0", "172.26.223.1", 55, 0, logrus.New())
	if err != nil {
		t.Fatal(err)
	}

	// parse ipv4 and ipv6 from address data output from the 'ifconfig' command
	addresses4, _, err := ipManager.parseAddressData([]string{data})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("addresses:", addresses4)

	if len(addresses4) != 2 {
		t.Fatalf("expected two addresses. saw %d", len(addresses4))
	}

	if addresses4[0] != "172.27.223.81" {
		t.Errorf("unexpected address %v", addresses4)
	}

	if addresses4[1] != "172.27.223.88" {
		t.Errorf("unexpected address %v", addresses4)
	}
}
