package system

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Comcast/Ravel/pkg/types"
	log "github.com/sirupsen/logrus"
)

// IP defines a wrapper on the ip command, which can be used to interface with the ip binary
type IP interface {
	SetARP() error

	AdvertiseMacAddress(addr string) error
	Add(addr string) error
	Add6(addr string) error
	Del(device string) error
	// Del6(addr, port string) error

	// return v4, v6 addrs
	Get() ([]string, []string, error)
	// for 4 or 6
	Compare4(have, want []string) (add, remove []string)
	Compare6(have, want []string) (add, remove []string)

	SetMTU(config map[types.ServiceIP]string, isIP6 bool) error

	Device(addr string, isV6 bool) string
	SetRPFilter() error

	Teardown(ctx context.Context, config4 map[types.ServiceIP]types.PortMap, config6 map[types.ServiceIP]types.PortMap) error
}

type ipManager struct {
	device        string
	gateway       string
	IPCommandPath string // the path to the 'ip' binary

	announce int
	ignore   int

	ctx    context.Context
	logger log.FieldLogger

	// interfaceGetMu locks operations that fetch interfaces so more than one don't run at once
	interfaceGetMu sync.Mutex
}

// NewIP creates a new ipManager struct for manging ip binary operations
func NewIP(ctx context.Context, device string, gateway string, announce, ignore int, logger log.FieldLogger) (*ipManager, error) {
	return &ipManager{
		device:         device,
		gateway:        gateway,
		announce:       announce,
		ignore:         ignore,
		IPCommandPath:  "/sbin/ip", // by default, rely on the path our official container uses (alpine)
		ctx:            ctx,
		logger:         logger,
		interfaceGetMu: sync.Mutex{},
	}, nil
}

func (i *ipManager) Get() ([]string, []string, error) {
	log.Infoln("ipManager fetching dummy interfaces...")
	return i.get()
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
		cmdCtx, cmdContextCancel := context.WithTimeout(i.ctx, time.Second*20)
		defer cmdContextCancel()
		cmd := exec.CommandContext(cmdCtx, "ifconfig", args...)
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
	cmdCtx, cmdContextCancel := context.WithTimeout(i.ctx, time.Second*20)
	defer cmdContextCancel()
	cmd := exec.CommandContext(cmdCtx, cmdLine, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipManager: unable to advertise arp. Saw error %s with output %s. addr=%s gateway=%s device=%s", err, string(out), addr, i.gateway, i.device)
	}
	return nil
}

func (i *ipManager) SetRPFilter() error {
	log.Debugln("ipManager: setting RPFilter")
	tunl0File := "/netconf/tunl0/rp_filter"
	allFile := "/netconf/all/rp_filter"
	log.Debugln("ipManager: seting rp_filter for 'all' and 'tunl0'")

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
	log.Debugf("ipManager: seting arp_announce for %s to %d\n", i.device, i.announce)
	log.Debugf("ipManager: seting arp_ignore for %s to %d\n", i.device, i.ignore)

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

func (i *ipManager) get() ([]string, []string, error) {
	iFaces, err := i.retrieveDummyIFaces()
	if err != nil {
		// return nil, nil, fmt.Errorf("ipManager: error running shell command ip -details link show | grep -B 2 dummy: %+v", err)
		return nil, nil, fmt.Errorf("ipManager: error running shell command ip link show | grep -B 2 dummy: %+v", err)
	}
	// log.Debugln("ipManager: get() done fetching dummy interfaces. parsing address data:", iFaces)

	// split them into v4 or v6 addresses
	return i.parseAddressData(iFaces)
}

// generate the target name of a device. This will be used in both adds and removals
func (i *ipManager) generateDeviceLabel(addr string, isIP6 bool) string {
	// log.Debugln("ipManager: creating device label for addr", addr)
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
	// log.Debugln("ipManager: adding dummy interface for addr", addr)
	device := i.generateDeviceLabel(addr, isIP6)
	// create the device
	args := []string{"link", "add", device, "type", "dummy"}
	log.Debugln("ipManager: adding ip using command: ip", args)

	cmdCtx, cmdContextCancel := context.WithTimeout(ctx, time.Second*20)
	defer cmdContextCancel()

	cmd := exec.CommandContext(cmdCtx, "ip", args...)
	out, err := cmd.CombinedOutput()
	// if it exists, we know we have already added the iface for it, and
	// the relevant address. Exit success from this method
	if err != nil && strings.Contains(string(out), "File exists") {
		// log.Debugln("ipManager: attempted to add interface, but it already exists")
		return nil
	}

	// if the error _does not_ indicate the file exists, we have a real error
	if err != nil {
		return fmt.Errorf("ipManager: failed to create device %s for addr %s: %v. Saw output: %s", device, addr, err, string(out))
	}

	// add the command to the specific interface we are using
	// if adding a v6 addr, this must be appended to the add command
	// or the add addr command fails silently
	if isIP6 {
		args = []string{"-6", "address", "add", addr, "dev", device}
	} else {
		args = []string{"address", "add", addr, "dev", device}
	}

	// wait what?! Why?!
	// if you add a v4/v6 address to a dummy interface immediately after creation,
	// it exits 0 with no output, but just....doesn't add the address
	// after much gnashing of teeth and head scratching I just added this
	time.Sleep(100 * time.Millisecond)

	cmdCtx, cmdContextCancel = context.WithTimeout(ctx, time.Second*20)
	defer cmdContextCancel()
	cmd = exec.CommandContext(cmdCtx, "ip", args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipManager: unable to add ip on second try address='%s' on device='%s' with args='%v'. %v. Saw output: %s", addr, device, args, err, string(out))
	}

	log.Debugln("ipManager: successfully added dummy loopback adapter with address", addr)
	return nil
}

func (i *ipManager) del(ctx context.Context, device string) error {
	if len(strings.TrimSpace(device)) == 0 { // dont try to delete blank devices, just let it go... too many unsanitized strings flying around
		// log.Warningln("Saw a del call for a device that was blank so it was ignored.")
		return nil
	}
	// log.Debugln("ipManager: deleting device with length", len(device), "named:", device)
	// create the device
	args := []string{"link", "del", device, "type", "dummy"}
	// log.Debugln("ipManager: deleting device with command: ip", args)

	cmdCtx, cmdContextCancel := context.WithTimeout(ctx, time.Second*20)
	defer cmdContextCancel()

	cmd := exec.CommandContext(cmdCtx, "ip", args...)
	out, err := cmd.CombinedOutput()
	// if it doesnt exist, this may be indicative of a bug in the add / remove code
	// but if it's already gone, no problem
	if err != nil && !strings.Contains(string(out), "Cannot find device") {
		return fmt.Errorf("ipManager: failed to delete device %s: %v", device, err)
	}

	return nil
}

// parseAddressData from the set off dummy interfaces, find out which is v4, v6
// input provided with ip -detail and grep'd for interface of type dummy so everything
// is pre-filtered
func (i *ipManager) parseAddressData(iFaces []string) ([]string, []string, error) {
	outV4 := []string{}
	outV6 := []string{}

	for _, iFace := range iFaces {
		// always ignore adapters that have `nodelocaldns` in them.  This prevents
		// Ravel from destroying adapters created by node-local-dns pods.
		// TODO - how can we only work with adapters that Ravel should care about, instead
		// of all dummy interfaces on the system?
		if strings.ContainsAny(iFace, "nodelocaldns") {
			// log.Infoln("Skipping adapter with name nodelocaldns")
			continue
		}

		// use our naming convention for virtual ifs 10.54.213.214 => 10_54_213_214
		// to identify if this is one of ours. No other system ifs use this convention
		if strings.Contains(iFace, "_") {
			outV4 = append(outV4, iFace)
			continue
		}

		outV6 = append(outV6, iFace)
	}

	sort.Sort(sort.StringSlice(outV4))
	sort.Sort(sort.StringSlice(outV6))
	return outV4, outV6, nil
}

func runPipeCommands(ctx context.Context, commandA []string, commandB []string) (*bytes.Buffer, error) {

	// create two processes to run
	commandAArgs := commandA[1:]
	commandBArgs := commandB[1:]
	c1 := exec.CommandContext(ctx, commandA[0], commandAArgs...)
	c2 := exec.CommandContext(ctx, commandB[0], commandBArgs...)

	// pipe the first process to the second process
	var err error
	c2.Stdin, err = c1.StdoutPipe()
	if err != nil {
		panic(err)
	}

	// make an output buffer and attach it to the output of command 2
	outputBuf := bytes.NewBuffer([]byte{})
	c2.Stdout = outputBuf

	// start the second process that will read from the first process
	err = c2.Start()
	if err != nil {
		return outputBuf, fmt.Errorf("error starting command 2: %w", err)
	}

	// start the first that pipes to the second and wait for it to finish
	err = c1.Run()
	if err != nil {
		return outputBuf, fmt.Errorf("error running command 1: %w", err)
	}

	// wait for the second process to finish
	err = c2.Wait()
	if err != nil {
		return outputBuf, fmt.Errorf("error waiting for command 2: %w", err)
	}

	return outputBuf, nil
}

// retrieveDummyIFaces tries to greb for interfaces with 'dummy' in the output from 'ip -details link show'.
func (i *ipManager) retrieveDummyIFaces() ([]string, error) {

	startTime := time.Now()
	defer func() {
		runDuration := time.Since(startTime)
		log.Infoln("ipManager: retrieveDummyIFaces took", runDuration)
	}()

	// mutex this operation to prevent overlapping queries
	// log.Debugln("ipManager: Retrieving dummy interfaces. Waiting to lock interfaceMu...")
	i.interfaceGetMu.Lock()

	// log.Debugln("ipManager: interfaceMu locked. starting commands")
	defer func() {
		i.interfaceGetMu.Unlock()
		// log.Infoln("ipManager: interfaceMu unlocked.")
	}()

	// create a context timeout for our processes
	ctx, ctxCancel := context.WithTimeout(i.ctx, time.Minute)
	defer ctxCancel()

	commandA := []string{i.IPCommandPath, "-details", "link", "show"}
	commandB := []string{"grep", "-B", "2", "dummy"}

	// run the commands piped together
	output, err := runPipeCommands(ctx, commandA, commandB)
	if err != nil {
		// if the error is `error waiting for command 2: exit status 1`, then that means there are no adapters,
		// because grep exits 1 when it does not find results.  We should gracefully handle this circumstance.
		if strings.Contains(err.Error(), "error waiting for command 2: exit status 1") {
			log.Debugln("ipManager: ip link show | grep -B 2 dummy did not find any adapters")
			return []string{}, nil
		}
		return []string{}, fmt.Errorf("ipManager: error running ip link show command: %w", err)
	}

	// list over the interfaces parsed from CLI output and append them into a slice
	iFaces := []string{}
	b2SplFromLines := strings.Split(output.String(), "\n")
	for _, l := range b2SplFromLines {
		if strings.Contains(l, "mtu") {
			awked := strings.Split(l, " ")
			if len(awked) >= 2 {
				iFace := strings.Replace(awked[1], ":", "", 1)
				iFaces = append(iFaces, iFace)
			}
		}
	}

	log.Debugln("ipManager: parsed ", len(iFaces), "interfaces")
	// log.Debugln("ipManager: retrieveDummyInterfaces completed")

	return iFaces, nil
}

func isV4Addr(addr string) bool {
	i := net.ParseIP(addr)
	if i.To4() == nil {
		return false
	}
	return true
}
