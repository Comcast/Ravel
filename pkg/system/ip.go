package system

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/comcast/ravel/pkg/types"
)

type IP interface {
	SetARP() error

	AdvertiseMacAddress(addr string) error
	Add(addr string) error
	Add6(addr string) error
	Del(addr string) error
	Del6(addr string) error

	// return v4, v6 addrs
	Get(config map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) ([]string, []string, error)
	// for 4 or 6
	Compare4(have, want []string) (add, remove []string)
	Compare6(have, want []string) (add, remove []string)

	Device(addr string, isV6 bool) string
	SetRPFilter() error

	Teardown(ctx context.Context, config4 map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) error
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

func (i *ipManager) Get(config4 map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) ([]string, []string, error) {
	return i.get(i.ctx, config4, config6)
}

func (i *ipManager) Device(addr string, isV6 bool) string { return i.generateDeviceLabel(addr, isV6) }
func (i *ipManager) Add(addr string) error                { return i.add(i.ctx, addr, false) }
func (i *ipManager) Add6(addr string) error               { return i.add(i.ctx, addr, true) }

func (i *ipManager) Del(addr string) error  { return i.del(i.ctx, addr, false) }
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

func (i *ipManager) Compare4(configured, desired []string) ([]string, []string) {
	return i.Compare(configured, desired, false)
}

func (i *ipManager) Compare6(configured, desired []string) ([]string, []string) {
	return i.Compare(configured, desired, true)
}

// pass in an array of v4 or
func (i *ipManager) Compare(configured, desired []string, v6 bool) ([]string, []string) {
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
			if !v6 && isV4Addr(caddr) {
				removals = append(removals, caddr)
			} else if v6 && !isV4Addr(caddr) {
				removals = append(removals, caddr)
			}
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

func (i *ipManager) Teardown(ctx context.Context, config4 map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) error {
	addressesv4, addressesv6, err := i.get(ctx, config4, config6)
	if err != nil {
		return err
	}
	errs := []string{}
	for _, address := range addressesv4 {
		err := i.del(ctx, address, false)
		if err != nil {
			errs = append(errs, address)
		}
	}

	for _, address := range addressesv6 {
		err := i.del(ctx, address, true)
		if err != nil {
			errs = append(errs, address)
		}
	}

	if len(errs) != 0 {
		return fmt.Errorf("encountered errors removing %d/%d addresses from %s. '%v'", len(errs), len(addressesv4)+len(addressesv6), i.device, errs)
	}
	return nil
}

func (i *ipManager) get(ctx context.Context, config4 map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) ([]string, []string, error) {
	// note that the ravel ip binary is NOT COMPATIBLE with the subcommand "ip link show type dummy"
	args := []string{"link", "show"}
	cmd := exec.CommandContext(ctx, "ip", args...)
	out, err := cmd.Output()

	if err != nil {
		return nil, nil, fmt.Errorf("error running shell command %s %s %s: %+v. Saw output: %s", "ip", "link", "show", err, string(out))
	}
	return i.parseAddressData(out, config4, config6)
}

// generate the target name of a device. This will be used in both adds and removals
func (i *ipManager) generateDeviceLabel(addr string, isIP6 bool) string {
	if isIP6 {
		// this code makes me sad but interface names are limited to 15 characters
		// strip spacer characters to reduce chance of collision and grab the end
		// of the address to create an if name we can affiliate with a known address
		// probably will never have to worry about it
		addrStripped := strings.Replace(addr, ":", "", -1)
		l := len(addrStripped)
		return string(addrStripped[l-15:])
	}
	return strings.Replace(addr, ".", "_", -1)
}

func (i *ipManager) add(ctx context.Context, addr string, isIP6 bool) error {
	device := i.generateDeviceLabel(addr, isIP6)
	// create the device
	args := []string{"link", "add", device, "type", "dummy"}
	cmd := exec.CommandContext(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	// if it already exists, this may be indicative of a bug in the add / remove code
	// but if it exists, leave it
	if err != nil && !strings.Contains(string(out), "File exists") {
		return fmt.Errorf("failed to create device %s for addr %s: %v", device, addr, err)
	}

	// generating a label in the form of <device>:<label> that can be used to look up VIPs later.
	args = []string{"address", "add", addr, "dev", device}
	cmd = exec.CommandContext(ctx, "ip", args...)
	out, err = cmd.CombinedOutput()
	if err != nil && strings.Contains(string(out), "File exists") {
		// XXX REMOVE THIS
		// This code exists to support migration from older versions of kube2ipvs that do not create interface labels
		// XXX REMOVE THIS

		{
			// DELETING
			cmd := exec.CommandContext(ctx, "ip", "address", "del", addr, "dev", device)
			err := cmd.Run()
			if err != nil {
				return fmt.Errorf("unable to add address. attempt to delete old address='%s' on device='%s' with no label failed. %v", addr, device, err)
			}
		}

		{
			// THEN ADDING
			cmd := exec.CommandContext(ctx, "ip", args...)
			err := cmd.Run()
			if err != nil {
				return fmt.Errorf("unable to add address='%s' on device='%s' with args='%v'. %v", addr, device, args, err)
			}
		}

	} else if err != nil {
		return fmt.Errorf("unable to add address='%s' on device='%s' with args='%v'. %v", addr, device, args, err)
	}
	return nil
}

func (i *ipManager) del(ctx context.Context, addr string, isIP6 bool) error {
	device := i.generateDeviceLabel(addr, isIP6)
	// create the device
	args := []string{"link", "del", device, "type", "dummy"}
	cmd := exec.CommandContext(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	// if it doesnt exist, this may be indicative of a bug in the add / remove code
	// but if it's already gone, no problem
	if err != nil && !strings.Contains(string(out), "Cannot find device") {
		return fmt.Errorf("failed to delete device %s for addr %s: %v", device, addr, err)
	}

	return nil
}

// returns a sorted set of addresses from `ip a` output for every address matching the deviceLabel
func (i *ipManager) parseAddressData(in []byte, config4 map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) ([]string, []string, error) {
	outV4 := []string{}
	outV6 := []string{}
	var ifName string

	buf := bytes.NewBuffer(in)
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		line := scanner.Text()
		// mtu line contains declaration of interface name
		if strings.Contains(line, "mtu") {
			// grab the if name
			declLineSplit := strings.Split(line, ":")
			if len(declLineSplit) > 2 {
				ifName = declLineSplit[1]
			} else {
				// don't compare against stale stuff
				ifName = ""
			}

			// search if list contains the v4 addr tag
			for v4 := range config4 {
				ipAsIfName := i.generateDeviceLabel(string(v4), false)
				if ifName == ipAsIfName {
					outV4 = append(outV4, ifName)
				}
			}

			// search if list contains the v6 addr tag
			for v6 := range config6 {
				ipAsIfName := i.generateDeviceLabel(string(v6), true)
				if ifName == ipAsIfName {
					outV6 = append(outV6, ifName)
				}
			}
		}
	}

	sort.Sort(sort.StringSlice(outV4))
	sort.Sort(sort.StringSlice(outV6))
	return outV4, outV6, nil
}

func isV4Addr(addr string) bool {
	i := net.ParseIP(addr)
	if i.To4() == nil {
		return false
	}
	return true
}
