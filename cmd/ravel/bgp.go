package main

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Comcast/Ravel/pkg/bgp"
	"github.com/Comcast/Ravel/pkg/stats"
	"github.com/Comcast/Ravel/pkg/system"
	"github.com/Comcast/Ravel/pkg/types"
)

// BGP configures IPVS, attracts packets in multi-master BGP mode
func BGP(ctx context.Context, logger logrus.FieldLogger) *cobra.Command {

	var cmd = &cobra.Command{
		Use:           "bgp",
		Short:         "run the rdei load balancer director in BGP mode",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long:          ``,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger.Infof("starting load balancer in bgp mode")

			config := NewConfig(cmd.Flags())
			logger.Debugf("got config %+v", config)

			// validate flags
			if err := config.Invalid(); err != nil {
				return err
			}

			// write IPVS Sysctl flags to director node
			if err := config.IPVS.WriteToNode(); err != nil {
				return err
			}

			// instantiate a watcher
			logger.Info("starting watcher")
			watcher, err := system.NewWatcher(ctx, config.KubeConfigFile, config.ConfigMapNamespace, config.ConfigMapName, config.ConfigKey, stats.KindBGP, config.DefaultListener.Service, config.DefaultListener.Port, logger)
			if err != nil {
				return err
			}

			// and Stats for the BGP VIPs.
			logger.Info("creating BGP stats")
			s, err := stats.NewStats(ctx, stats.KindBGP, config.Stats.Interface, config.Stats.ListenAddr, config.Stats.ListenPort, config.Stats.Interval, logger)
			if err != nil {
				return fmt.Errorf("failed to initialize metrics. %v", err)
			}
			go func() {
				logger.Debug("executing BGP stats closure")
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
			logger.Debug("checking if BGP stats enabled")
			if config.Stats.Enabled {
				if err := s.EnableBPFStats(); err != nil {
					return fmt.Errorf("failed to initialize BPF capture. if=%v sa=%s %v", config.Stats.Interface, config.Stats.ListenAddr, err)
				}
			}

			// emit the version metric
			emitVersionMetric(stats.KindBGP, config.ConfigMapNamespace, config.ConfigMapName, config.ConfigKey)

			/* cmd/director.go does this, but original cmd/bgp.go did not. Should this one?
						// Starting up control port.
			            logger.Infof("starting listen controllers on %v", config.Coordinator.Ports)
			            cm := NewCoordinationMetrics(stats.KindDirector)
			            for _, port := range config.Coordinator.Ports {
			                go listenController(port, cm, logger)
			            }

			            // listen for health
			            logger.Info("starting health endpoint")
			            go util.ListenForHealth(config.Net.Interface, 10201, logger)
			*/

			// instantiate a new IPVS manager
			logger.Info("Initializing ipvs helper")
			ipvs, err := system.NewIPVS(ctx, config.Net.PrimaryIP, config.IPVS.WeightOverride, config.IPVS.IgnoreCordon, logger)
			if err != nil {
				return err
			}

			// instantiate an IP helper for loopback
			logger.Info("Initializing loopback ip helper")
			ipLoopback, err := system.NewIP(ctx, config.Net.LocalInterface, config.Net.Gateway, config.Arp.LoAnnounce, config.Arp.LoIgnore, logger)
			if err != nil {
				return err
			}
			if err := ipLoopback.SetARP(); err != nil {
				return err
			}

			// instantiate an IP helper for primary interface
			logger.Info("initializing primary helper")
			ipPrimary, err := system.NewIP(ctx, config.Net.Interface, config.Net.Gateway, config.Arp.PrimaryAnnounce, config.Arp.PrimaryIgnore, logger)
			if err != nil {
				return err
			}
			if err := ipPrimary.SetARP(); err != nil {
				return err
			}

			// instantiate BGP handler
			bgpController := bgp.NewBGPDController(config.BGP.Binary, logger)

			worker, err := bgp.NewBGPWorker(ctx, config.ConfigKey, watcher, ipLoopback, ipPrimary, ipvs, bgpController, logger)
			if err != nil {
				return err
			}

			err = worker.Start()
			if err != nil {
				return err
			}

			// catching exit signals sent from the parent context
			<-ctx.Done()
			return worker.Stop()
		},
	}

	return cmd
}
