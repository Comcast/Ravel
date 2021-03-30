package bgp

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// The Controller provides an interface for configuring BGP.
// Feed a controller a list of VIP addresses that require configuration,
// and it will manage the whole add/remove/change process.
type Controller interface {

	// Get returns the addresses currently in the BGP RIB
	Get(ctx context.Context) ([]string, error)

	// Set receives a list of ip addresses and performs the necessary
	// steps to configure each address in BGP.
	Set(ctx context.Context, addresses, configuredAddresses []string, communities []string) error

	// SetV6 set, for v6.  Very similar to above function
	SetV6(ctx context.Context, addresses []string, communities []string) error

	// Teardown removes all addresses from BGP.
	// Perhaps this will never be applied.
	Teardown(context.Context) error
}

type GoBGPDController struct {
	commandPath string
	logger      logrus.FieldLogger
}

// Get fetches a list of configured addresses in gobgp
func (g *GoBGPDController) Get(ctx context.Context) ([]string, error) {
	configuredAddrs := []string{}

	args := []string{"global", "rib", "-a", "ipv4"}
	cmd := exec.CommandContext(ctx, g.commandPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return configuredAddrs, fmt.Errorf("could not return list of configured addresses from gobgp: %v", err)
	}

	return parseRIBOutput(out), nil
}

func parseRIBOutput(output []byte) []string {
	outputAsList := strings.Split(string(output), "\n")
	addresses := []string{}
	// start at 1 to skip columnar format line
	for i := 1; i < len(outputAsList); i++ {
		out := outputAsList[i]
		fields := strings.Fields(out)
		if len(fields) > 2 {
			trimCidr := strings.Replace(fields[1], "/32", "", 1)
			addresses = append(addresses, trimCidr)
		}
	}
	return addresses
}

// Set configures the ipvsadm rules for ipv4 with an optional set of community strings.  If a community is not set
// or blank, then it will not be used.
func (g *GoBGPDController) Set(ctx context.Context, addresses, configuredAddresses []string, communities []string) error {
	// quick check to see if this is already configured. If so, no need to push
	// another network update
	toAdd := []string{}
	for _, addr := range addresses {
		var found bool
		for _, configured := range configuredAddresses {
			if addr == configured {
				found = true
				break
			}
		}
		if !found {
			toAdd = append(toAdd, addr)
		}
	}
	// $PATH/gobgp global rib -a ipv4 add 10.54.213.148/32
	for _, address := range toAdd {
		cidr := address + "/32"
		g.logger.Debugf("Advertising route to %s", cidr)
		args := []string{"global", "rib", "-a", "ipv4", "add", cidr}
		// if communities are supplied, add it here as a community
		if len(communities) > 0 {
			// add community cli option
			args = append(args, "community")
			// add each community with a comma after it like so: 100:100:100,200:200:200
			for _, c := range communities {
				args = append(args, c, ",")
			}
			// remove any trailing commas on the communities arguments
			if args[len(args)-1] == "," {
				args = args[:len(args)-1]
			}
		}
		if err := exec.CommandContext(ctx, g.commandPath, args...).Run(); err != nil {
			return fmt.Errorf("adding route %s with %s: %s", cidr, strings.Join(append([]string{g.commandPath}, args...), " "), err)
		}
	}
	return nil
}

// SetV6 set ipvsadm rule with ipv6 syntax.  If a blank community slice is supplied, no community is advertised.
func (g *GoBGPDController) SetV6(ctx context.Context, addresses []string, communities []string) error {
	// $PATH/gobgp global rib -a ipv6 add [2001:558:1044:1ae:10ad:ba1a:0000:0007]/128
	for _, address := range addresses {
		cidr := address + "/128"
		g.logger.Debugf("Advertising route to %s", cidr)
		args := []string{"global", "rib", "-a", "ipv6", "add", cidr}
		// if communities are supplied, add it here as a community
		if len(communities) > 0 {
			// add community cli option
			args = append(args, "community")
			// add each community with a comma after it like so: 100:100:100,200:200:200
			for _, c := range communities {
				args = append(args, c, ",")
			}
			// remove any trailing commas on the communities arguments
			if args[len(args)-1] == "," {
				args = args[:len(args)-1]
			}
		}
		if err := exec.CommandContext(ctx, g.commandPath, args...).Run(); err != nil {
			return fmt.Errorf("adding route %s with %s: %s", cidr, strings.Join(append([]string{g.commandPath}, args...), " "), err)
		}
	}
	return nil
}

func (g *GoBGPDController) Teardown(context.Context) error {
	// I suspect that we don't want to remove all addresses' routes,
	// but rather one at a time, if any at all.
	g.logger.Info("Tear down: Let's leave things how they are.")
	return nil
}

func NewBGPDController(executablePath string, logger logrus.FieldLogger) *GoBGPDController {
	return &GoBGPDController{commandPath: executablePath, logger: logger}
}
