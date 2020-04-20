package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/comcast/ravel/pkg/haproxy"
	"github.com/spf13/cobra"

	"github.com/comcast/ravel/pkg/iptables"
	"github.com/comcast/ravel/pkg/realserver"
	"github.com/comcast/ravel/pkg/stats"
	"github.com/comcast/ravel/pkg/system"
	"github.com/comcast/ravel/pkg/types"
	"github.com/comcast/ravel/pkg/util"
)

// RealServer creates the realserver command for kube2ipvs
func RealServer(ctx context.Context, logger logrus.FieldLogger) *cobra.Command {

	var cmd = &cobra.Command{
		Use:   "realserver",
		Short: "kube2ipvs realserver",
		Long: `
kube2ipvs realserver will run the kube2ipvs daemon in realserver mode,
where it will continuously check the kubernetes API for updates to both
node heath as well as the client port configuration.

In realserver mode, kube2ipvs will directly interact with iptables in order
to prune rules that exist, but no longer apply, and to create rules that
are missing from the configuration.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			config := NewConfig(cmd.Flags())
			logger.Debugf("got config %+v", config)

			if config.FlagModeEnv {
				if err := config.retrieveNodeConfig(); err != nil {
					return err
				}
			}

			// validate flags
			if err := config.Invalid(); err != nil {
				return err
			}

			// instantiate a watcher
			watcher, err := system.NewWatcher(ctx, config.KubeConfigFile, config.ConfigMapNamespace, config.ConfigMapName, config.ConfigKey, stats.KindRealServer, config.DefaultListener.Service, config.DefaultListener.Port, logger)
			if err != nil {
				return err
			}

			// initialize statistics
			s, err := stats.NewStats(ctx, stats.KindRealServer, config.Stats.Interface, config.Stats.ListenAddr, config.Stats.ListenPort, config.Stats.Interval, logger)
			if err != nil {
				return fmt.Errorf("failed to initialize metrics. %v", err)
			}
			go func() {
				configs := make(chan *types.ClusterConfig, 100)
				watcher.ConfigMap(ctx, "stats", configs)
				for {
					select {
					case <-ctx.Done():
						return
					case c := <-configs:
						s.UpdateConfig(c)
					}
				}
			}()
			if config.Stats.Enabled {
				if err := s.EnableBPFStats(); err != nil {
					return fmt.Errorf("failed to initialize BPF capture. if=%v sa=%s %v", config.Stats.Interface, config.Stats.ListenAddr, err)
				}
			}
			// emit the version metric
			emitVersionMetric(stats.KindRealServer, config.ConfigMapNamespace, config.ConfigMapName, config.ConfigKey)

			// listen for health
			go util.ListenForHealth(config.Net.Interface, 10200, logger)

			// instantiate an IP helper for loopback
			logger.Info("initializing loopback helper")
			ipLoopback, err := system.NewIP(ctx, config.Net.LocalInterface, config.Net.Gateway, config.Arp.LoAnnounce, config.Arp.LoIgnore, logger)
			if err != nil {
				return err
			}

			// instantiate an IP helper for primary interface
			logger.Info("initializing primary helper")
			ipPrimary, err := system.NewIP(ctx, config.Net.Interface, config.Net.Gateway, config.Arp.PrimaryAnnounce, config.Arp.PrimaryIgnore, logger)
			if err != nil {
				return err
			}

			// instantiate an iptables interface
			logger.Info("initializing iptables helper")
			ipt, err := iptables.NewIPTables(ctx, stats.KindRealServer, config.ConfigKey, config.PodCIDRMasq, config.IPTablesChain, config.IPTablesMasq, logger)
			if err != nil {
				return err
			}

			// instantiate a new IPVS manager
			logger.Info("initializing ipvs helper")
			ipvs, err := system.NewIPVS(ctx, config.Net.PrimaryIP, config.IPVS.WeightOverride, config.IPVS.IgnoreCordon, logger)
			if err != nil {
				return err
			}

			// instantiate the realserver worker.
			logger.Info("initializing realserver")
			haproxy, err := haproxy.NewHAProxySet(ctx, "/usr/sbin/haproxy", "/etc/ravel", logger)
			if err != nil {
				return err
			}
			worker, err := realserver.NewRealServer(ctx, config.NodeName, config.ConfigKey, watcher, ipPrimary, ipLoopback, ipvs, ipt, config.ForcedReconfigure, haproxy, logger)
			if err != nil {
				return err
			}

			logger.Infof("starting continuous poll to find director, using 127.0.0.1:%d", config.Coordinator.Ports[0])
			cm := NewCoordinationMetrics(stats.KindRealServer)
			return blockForever(ctx, worker, config.Coordinator.Ports[0], config.FailoverTimeout, cm, logger)

		},
	}
	return cmd
}

func blockForever(ctx context.Context, worker realserver.RealServer, port, maxTries int, cm *coordinationMetrics, logger logrus.FieldLogger) error {
	controlChan := make(chan bool)
	go watchForMaster(ctx, port, controlChan)

	tries := maxTries
	lastMasterStatus := true
	for { // ever
		select {
		case masterRunning := <-controlChan:
			cm.Check(masterRunning)
			if masterRunning && masterRunning != lastMasterStatus {
				logger.Info("got updated control message. stopping worker")
				cm.Running(false)
				if err := worker.Stop(); err != nil {
					return err
				}
			} else if masterRunning != lastMasterStatus && tries >= maxTries {
				cm.Running(true)
				logger.Info("got updated control message. starting worker")
				if err := worker.Start(); err != nil {
					return err
				}
			} else if masterRunning != lastMasterStatus {
				// increment unavailability counter
				cm.Hazard()
				logger.Warnf("director unavailable. %d/%d attempts before restart", tries, maxTries)
				tries++
				continue
			}
			lastMasterStatus = masterRunning
			tries = 1
		case <-ctx.Done():
			// catching exit signals sent from the parent context
			return worker.Stop()
		}
	}
	return nil
}

func watchForMaster(ctx context.Context, port int, controlChan chan bool) {
	// once per second, attempt to connect to the master.
	// record connection success / failure in  boolean channel.
	// values of `true` indicate that the worker must clean up
	// and stop.
	for {
		if connectToMaster(port) {
			controlChan <- true
		} else {
			controlChan <- false
		}
		<-time.After(1000 * time.Millisecond)
	}
}

func connectToMaster(port int) bool {
	addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	conn, err := net.DialTCP("tcp4", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// connection settings to kill this thing pronto
	conn.SetLinger(0)
	conn.SetNoDelay(true)
	conn.SetKeepAlive(false)

	return true

}
