package bgp

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Sirupsen/logrus"
)

// The Controller provides an interface for configuring BGP.
// Feed a controller a list of VIP addresses that require configuration,
// and it will manage the whole add/remove/change process.
type Controller interface {

	// Set receives a list of ip addresses and performs the necessary
	// steps to configure each address in BGP.
	Set(ctx context.Context, addresses []string) error

	// Teardown removes all addresses from BGP.
	// Perhaps this will never be applied.
	Teardown(context.Context) error
}

type GoBGPDController struct {
	commandPath string
	logger      logrus.FieldLogger
}

func (g *GoBGPDController) Set(ctx context.Context, addresses []string) error {
	// $PATH/gobgp global rib -a ipv4 add 10.54.213.148/32
	for _, address := range addresses {
		cidr := address + "/32"
		g.logger.Debugf("Advertising route to %s", cidr)
		args := []string{"global", "rib", "-a", "ipv4", "add", cidr}
		if err := exec.CommandContext(ctx, g.commandPath, args...).Run(); err != nil {
			return fmt.Errorf("adding route %s with %s: %s", cidr, strings.Join(append([]string{g.commandPath}, args...), " "), err)
		}
	}
	return nil
}

func (g *GoBGPDController) Teardown(context.Context) error {
	// I suspect that we don't want to remove all addresses' routes,
	// but rather one at a time, if any at all.
	g.logger.Info("Tear down ALL BGP routes")
	return nil
}

func NewBGPDController(executablePath string, logger logrus.FieldLogger) *GoBGPDController {
	return &GoBGPDController{commandPath: executablePath, logger: logger}
}
