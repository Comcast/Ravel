package system

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
)

// TODO: labels for director versus non-director?
const deviceLabel string = "k2i"
const deviceLabel6 string = "10ad:ba1a"

type IP interface {
	SetARP() error

	AdvertiseMacAddress(addr string) error
	Add(addr string) error
	Del(addr string) error
	Add6(addr string) error
	Del6(addr string) error

	Get() ([]string, error)
	Get6() ([]string, error)
	Compare(have, want []string) (add, remove []string)

	Device() string
	SetRPFilter() error

	Teardown(ctx context.Context) error
}

type ipManager struct {
	device  string
	gateway string

	announce int
	ignore   int

	ctx    context.Context
	logger logrus.FieldLogger
}

func NewIP(ctx context.Context, device string, gateway string, announce, ignore int, logger logrus.FieldLogger) (IP, error) {
	return &ipManager{
		device:   device,
		gateway:  gateway,
		announce: announce,
		ignore:   ignore,
		ctx:      ctx,
		logger:   logger,
	}, nil
}

func (i *ipManager) Get() ([]string, error) {
	return i.get(i.ctx, true, false)
}

func (i *ipManager) Get6() ([]string, error) {
	return i.get(i.ctx, false, true)
}

func (i *ipManager) Device() string        { return i.device }
func (i *ipManager) Add(addr string) error { return i.add(i.ctx, addr, false) }

func (i *ipManager) Del(addr string) error  { return i.del(i.ctx, addr, false) }
func (i *ipManager) Add6(addr string) error { return i.add(i.ctx, addr, true) }
func (i *ipManager) Del6(addr string) error { return i.del(i.ctx, addr, true) }

// AdvertiseMacAddress does a gratuitous ARP a specific VIP on a specific interface.
// Exec's the command: arping -c 1 -s $VIP_IP $gateway_ip -I $interface
// That's going to ask for the MAC address of $gateway_ip, sending the Who-has ARP
// packet out of $interface. The intent is to get the $gateway_ip to associate
// $interface's MAC (ethernet) address with the VIP. The Who-has ARP packet
// tricks the gateway into putting $interface's MAC address in its own ARP table
// with the VIP as the associated IP address.
func (i *ipManager) AdvertiseMacAddress(addr string) error {
	// `arping -c 1 -s $VIP_IP $gateway_ip -I $interface`
	cmdLine := "/usr/sbin/arping"
	args := []string{"-c", "1", "-s", addr, i.gateway, "-I", i.device}
	cmd := exec.CommandContext(i.ctx, cmdLine, args...)
	_, err := cmd.CombinedOutput()
	if err != nil {
		switch {
		case err.Error() == "exit status 1":
			return fmt.Errorf("/usr/sbin/arping saw exit status 1; IP address is already in use on server addr=%s gateway=%s device=%s err=%s", addr, i.gateway, i.device, err)
		case err.Error() == "exit status 2":
			return fmt.Errorf("/usr/sbin/arping saw exit status 2; ethernet device is down addr=%s gateway=%s device=%s err=%s", addr, i.gateway, i.device, err)
		default:
			return fmt.Errorf("unable to clear arp table for addr=%s gateway=%s device=%s err=%s", addr, i.gateway, i.device, err)
		}
	}
	return nil
}

func (i *ipManager) SetRPFilter() error {
	tunl0File := "/netconf/tunl0/rp_filter"
	allFile := "/netconf/all/rp_filter"
	i.logger.Debugf("seting rp_filter for 'all' and 'tunl0'")

	fAll, err := os.OpenFile(allFile, os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer fAll.Close()

	fTunl, err := os.OpenFile(tunl0File, os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer fAll.Close()

	_, err = fAll.Write([]byte("0"))
	if err != nil {
		return err
	}
	_, err = fTunl.Write([]byte("0"))
	if err != nil {
		return err
	}

	return nil

}

func (i *ipManager) SetARP() error {
	announceFile := fmt.Sprintf("/netconf/%s/arp_announce", i.device)
	ignoreFile := fmt.Sprintf("/netconf/%s/arp_ignore", i.device)
	i.logger.Debugf("seting arp_announce for %s to %d", i.device, i.announce)
	i.logger.Debugf("seting arp_ignore for %s to %d", i.device, i.ignore)

	fAnnounce, err := os.OpenFile(announceFile, os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer fAnnounce.Close()

	fIgnore, err := os.OpenFile(ignoreFile, os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer fIgnore.Close()

	_, err = fAnnounce.Write([]byte(strconv.Itoa(i.announce)))
	if err != nil {
		return err
	}

	_, err = fIgnore.Write([]byte(strconv.Itoa(i.ignore)))
	if err != nil {
		return err
	}

	return nil
}

func (i *ipManager) Compare(configured, desired []string) ([]string, []string) {
	removals := []string{}
	additions := []string{}

	for _, caddr := range configured {
		found := false
		for _, daddr := range desired {
			if caddr == daddr {
				found = true
				break
			}
		}
		if !found {
			removals = append(removals, caddr)
		}
	}

	for _, daddr := range desired {
		found := false
		for _, caddr := range configured {
			if caddr == daddr {
				found = true
				break
			}
		}
		if !found {
			additions = append(additions, daddr)
		}
	}

	return removals, additions
}

func (i *ipManager) Teardown(ctx context.Context) error {
	addresses, err := i.get(ctx, true, true)
	if err != nil {
		return err
	}
	errs := []string{}
	for _, address := range addresses {
		err := i.del(ctx, address, strings.Contains(address, deviceLabel6))
		if err != nil {
			errs = append(errs, address)
		}
	}
	if len(errs) != 0 {
		return fmt.Errorf("encountered errors removing %d/%d addresses from %s. '%v'", len(errs), len(addresses), i.device, errs)
	}
	return nil
}

func (i *ipManager) get(ctx context.Context, IPv4, IPv6 bool) ([]string, error) {
	cmd := exec.CommandContext(ctx, "ip", "addr", "show", "dev", i.device)
	out, err := cmd.Output()

	if err != nil {
		return nil, fmt.Errorf("error running shell command %s %s %s %s %s: %+v", "ip", "addr", "show", "dev", i.device, err)
	}
	return parseAddressData(out, IPv4, IPv6)
}

func (i *ipManager) add(ctx context.Context, addr string, isIP6 bool) error {
	// generating a label in the form of <device>:<label> that can be used to look up VIPs later.
	args := []string{"address", "add", addr, "dev", i.device}
	if !isIP6 {
		label := fmt.Sprintf("%s:%s", i.device, deviceLabel)
		args = append(args, "label", label)
	}
	cmd := exec.CommandContext(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil && strings.Contains(string(out), "File exists") {
		// XXX REMOVE THIS
		// This code exists to support migration from older versions of kube2ipvs that do not create interface labels
		// XXX REMOVE THIS

		{
			// DELETING
			cmd := exec.CommandContext(ctx, "ip", "address", "del", addr, "dev", i.device)
			err := cmd.Run()
			if err != nil {
				return fmt.Errorf("unable to add address. attempt to delete old address='%s' on device='%s' with no label failed. %v", addr, i.device, err)
			}
		}

		{
			// THEN ADDING
			cmd := exec.CommandContext(ctx, "ip", args...)
			err := cmd.Run()
			if err != nil {
				return fmt.Errorf("unable to add address='%s' on device='%s' with args='%v'. %v", addr, i.device, args, err)
			}
		}

	} else if err != nil {
		return fmt.Errorf("unable to add address='%s' on device='%s' with args='%v'. %v", addr, i.device, args, err)
	}
	return nil
}

func (i *ipManager) del(ctx context.Context, addr string, isIP6 bool) error {
	// generating a label in the form of <device>:<label> that can be used to look up VIPs later.
	args := []string{"address", "del", addr, "dev", i.device}
	if !isIP6 {
		label := fmt.Sprintf("%s:%s", i.device, deviceLabel)
		args = append(args, "label", label)
	}

	// do the delete including the label
	cmd := exec.CommandContext(ctx, "ip", args...)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("unable to delete address='%s' on device='%s' with args='%v'. %v", addr, i.device, args, err)
	}
	return nil
}

// returns a sorted set of addresses from `ip a` output for every address matching the deviceLabel
func parseAddressData(in []byte, IPv4, IPv6 bool) ([]string, error) {
	out := []string{}

	buf := bytes.NewBuffer(in)
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		line := scanner.Text()
		if IPv4 && strings.Contains(line, deviceLabel) {
		} else if IPv6 && strings.Contains(line, deviceLabel6) {
		} else {
			continue
		}

		// '    inet 172.27.223.81/32 scope global enp6s0:k2i'
		line = strings.TrimSpace(line)
		// 'inet 172.27.223.81/32 scope global enp6s0:k2i'
		tokens := strings.Split(line, " ")
		// '[inet, 172.27.223.81/32, scope, global, enp6s0:k2i]'
		if len(tokens) < 2 {
			return nil, fmt.Errorf("not enough fields in address definition. expected >1, saw %d for line '%s'", len(tokens), line)
		}

		addr := tokens[1]
		// '172.27.223.81/32'
		pair := strings.Split(addr, "/")
		// '[172.27.223.81, 32]'
		out = append(out, pair[0])
		// out = append(out, addr) // XXX TODO preserve the /32?...
	}

	sort.Sort(sort.StringSlice(out))
	return out, nil
}
