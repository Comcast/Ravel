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
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/comcast/ravel/pkg/types"
)

type IP interface {
	SetARP() error

	AdvertiseMacAddress(addr string) error
	Add(addr string) error
	Add6(addr string) error
	Del(device string) error
	// Del6(addr, port string) error

	// return v4, v6 addrs
	Get(config map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) ([]string, []string, error)
	// for 4 or 6
	Compare4(have, want []string) (add, remove []string)
	Compare6(have, want []string) (add, remove []string)

	SetMTU(config map[types.ServiceIP]string, isIP6 bool) error

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

func (i *ipManager) Device(addr string, isV6 bool) string {
	return i.generateDeviceLabel(addr, isV6)
}
func (i *ipManager) Add(addr string) error  { return i.add(i.ctx, addr, false) }
func (i *ipManager) Add6(addr string) error { return i.add(i.ctx, addr, true) }

func (i *ipManager) Del(device string) error { return i.del(i.ctx, device) }

func (i *ipManager) SetMTU(config map[types.ServiceIP]string, isIP6 bool) error {
	for ip, mtu := range config {
		// guard against dated provisioner versions (bulkhead deploy), erroneous configurations
		// otherwise, don't skip standard (1500), could be setting back from a different MTU
		if mtu == "" {
			continue
		}

		// convert to int for validation
		backendAsInt, err := strconv.Atoi(mtu)
		if err != nil {
			i.logger.Warnf("VIP %s was unable to convert MTU field to int from string %s: %v. Skipping", ip, mtu, err)
			continue
		}

		if backendAsInt < 1500 || backendAsInt > 9000 {
			i.logger.Warnf("mtu value for VIP %s was out of valid range 1500-9000: %d. Skipping...", ip, backendAsInt)
		}

		// create the device name
		dev := i.generateDeviceLabel(string(ip), isIP6)

		// then set args and either set or ensure parity on the interface

		args := []string{dev, "mtu", mtu}
		cmd := exec.CommandContext(i.ctx, "ifconfig", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("error setting mtu on device %s: %v. Saw output: %v", dev, err, string(out))
		}
	}
	return nil
}

// AdvertiseMacAddress does a gratuitous ARP a specific VIP on a specific interface.
// Exec's the command: arping -c 1 -s $VIP_IP $gateway_ip -I $interface
// That's going to ask for the MAC address of $gateway_ip, sending the Who-has ARP
// packet out of $interface. The intent is to get the $gateway_ip to associate
// $interface's MAC (ethernet) address with the VIP. The Who-has ARP packet
// tricks the gateway into putting $interface's MAC address in its own ARP table
// with the VIP as the associated IP address.
func (i *ipManager) AdvertiseMacAddress(addr string) error {
	// `arping -c 1 -s $VIP_IP $gateway_ip -I $interface`
	// use primary no matter what device we are using
	cmdLine := "/usr/sbin/arping"
	args := []string{"-c", "1", "-s", addr, i.gateway, "-I", i.device}
	cmd := exec.CommandContext(i.ctx, cmdLine, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to advertise arp. Saw error %s with output %s. addr=%s gateway=%s device=%s", err, string(out), addr, i.gateway, i.device)
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
// TODO: Is the v6 flag not needed anymore
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

func (i *ipManager) Teardown(ctx context.Context, config4 map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) error {
	// we do NOT want to tear down any interfaces. Additions and removals should
	// handled by runtime which should be running continuously; why rip out existing
	//  backends in the event of a mistaken shutdown or crash loop

	// TODO: Is there anything else we want to cleanup?
	return nil
}

func (i *ipManager) get(ctx context.Context, config4 map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) ([]string, []string, error) {
	// grab all v4 devices
	args := []string{"-4", "a"}
	cmd := exec.CommandContext(ctx, "ip", args...)
	outv4, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("error running shell command %s %s %s: %+v. Saw output: %s", "ip", "link", "show", err, string(outv4))
	}

	// all v6 devices
	args = []string{"-6", "a"}
	cmd = exec.CommandContext(ctx, "ip", args...)
	outv6, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("error running shell command %s %s %s: %+v. Saw output: %s", "ip", "link", "show", err, string(outv6))
	}
	return i.parseAddressData(outv4, outv6, config4, config6)
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
		return fmt.Errorf("failed to create device %s for addr %s: %v. Saw output: %s", device, addr, err, string(out))
	}

	// add the command to the specific interface we are using
	// if adding a v6 addr, this must be appended to the add command
	// or the add addr command fails silently
	if isIP6 {
		args = []string{"-6", "address", "add", addr, "dev", device}
		// wait what?! Why?!
		// if you add a v6 address to a dummy interface immediately after creation,
		// it exits 0 with no output, but just....doesn't work
		// after much gnashing of teeth and head scratching I just added this
		time.Sleep(100 * time.Millisecond)
	} else {
		args = []string{"address", "add", addr, "dev", device}
	}
	cmd = exec.CommandContext(ctx, "ip", args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to add address='%s' on device='%s' with args='%v'. %v", addr, device, args, err)
	}

	return nil
}

func (i *ipManager) del(ctx context.Context, device string) error {
	// create the device
	args := []string{"link", "del", device, "type", "dummy"}
	cmd := exec.CommandContext(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	// if it doesnt exist, this may be indicative of a bug in the add / remove code
	// but if it's already gone, no problem
	if err != nil && !strings.Contains(string(out), "Cannot find device") {
		return fmt.Errorf("failed to delete device %s: %v", device, err)
	}

	return nil
}

// returns a sorted set of addresses from `ip a` output for every address matching the deviceLabel
func (i *ipManager) parseAddressData(inv4 []byte, inv6 []byte, config4 map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) ([]string, []string, error) {
	outV4 := []string{}
	outV6 := []string{}
	var ifName string

	// filter out interfaces used by the system
	systemIfaces := []string{
		"po", // primary if
		"lo",
		"docker",
		"enp",  // bond interfaces enpxxx
		"en0",  // bond interfaces enox
		"ens1", // bond interfaces ens1xx
		// v4/v6 tunnels
		"ip6tnl",
		"tun",
		"tunl",
		"veth", // realserver virtual eth
		"cali", // calico interfaces
	}

	buf := bytes.NewBuffer(inv4)
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
				// don't compare against stale stuff from previous loop iters
				ifName = ""
			}

			if ifName != "" {
				// if not a system iface, we configured it. Append to list on potential names
				system := false
				for _, systemIf := range systemIfaces {
					if strings.Contains(ifName, systemIf) {
						system = true
						break
					}
				}
				if system == false {
					outV4 = append(outV4, strings.TrimSpace(ifName))
				}
			}
		}
	}

	// do it again for v6
	buf = bytes.NewBuffer(inv6)
	scanner = bufio.NewScanner(buf)
	for scanner.Scan() {
		line := scanner.Text()
		// mtu line contains declaration of interface name
		if strings.Contains(line, "mtu") {
			// grab the if name
			declLineSplit := strings.Split(line, ":")
			if len(declLineSplit) > 2 {
				ifName = declLineSplit[1]
			} else {
				// don't compare against stale stuff from previous loop iters
				ifName = ""
			}

			if ifName != "" {
				// if not a system iface, we configured it. Append to list on potential names
				system := false
				for _, systemIf := range systemIfaces {
					if strings.Contains(ifName, systemIf) {
						system = true
						break
					}
				}
				if system == false {
					// ip -4 a shows all v4 but not v6, but ip -6 a shows v4 and v6
					// so filter those out
					ifNameTrimmed := strings.TrimSpace(ifName)
					isV4 := false
					// NEVER add anything that could have been in v4 to this map; otherwise
					// it could be added to the removalV6 routine (see comment above)
					for ip := range config4 {
						dev := i.generateDeviceLabel(string(ip), false)
						if dev == ifNameTrimmed {
							isV4 = true
							break
						}
					}
					if !isV4 {
						outV6 = append(outV6, ifNameTrimmed)
					}
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
