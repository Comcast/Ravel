package system

import (
	"reflect"
	"testing"
)

func TestDiffAddressSets(t *testing.T) {
	have := []string{"one", "two", "three"}
	want := []string{"two", "three", "four"}

	instance := &ipManager{}
	remove, add := instance.Compare(have, want)
	if !reflect.DeepEqual(add, []string{"four"}) {
		t.Fatalf("expected 'four' to be added. saw %v", add)
	}
	if !reflect.DeepEqual(remove, []string{"one"}) {
		t.Fatalf("expected 'one' to be removed. saw %v", remove)
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

	addresses, err := parseAddressData([]byte(data), true, true)
	if err != nil {
		t.Fatal(err)
	}

	if len(addresses) != 2 {
		t.Fatalf("expected two addresses. saw %d", len(addresses))
	}

	if addresses[0] != "172.27.223.81" {
		t.Errorf("unexpected address %v", addresses)
	}

	if addresses[1] != "172.27.223.88" {
		t.Errorf("unexpected address %v", addresses)
	}
}
