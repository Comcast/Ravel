package main

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Comcast/Ravel/pkg/bgp"
	"github.com/Comcast/Ravel/pkg/stats"
	"github.com/Comcast/Ravel/pkg/system"
	"github.com/Comcast/Ravel/pkg/watcher"
)

// BGP_DIRECTOR configures IPVS, attracts packets in multi-master BGP_DIRECTOR mode
func BGP_DIRECTOR(ctx context.Context, logger logrus.FieldLogger) *cobra.Command {

	var cmd = &cobra.Command{
		Use:           "bgp",
		Short:         "run the rdei load balancer director in BGP_DIRECTOR mode",
		SilenceUsage:  false,
		SilenceErrors: true,
		Long:          ``,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log.Debugln("BGP_DIRECTOR: Ravel starting in BGP_DIRECTOR mode")

			config := NewConfig(cmd.Flags())
			logger.Debugf("BGP_DIRECTOR: Got config %+v", config)

			// validate flags
			if err := config.Invalid(); err != nil {
				return err
			}
			log.Debugln("BGP_DIRECTOR: Done validating config flags")

			// write IPVS Sysctl flags to director node
			if err := config.IPVS.WriteToNode(); err != nil {
				return err
			}
			log.Debugln("BGP_DIRECTOR: Done writing IPVS proc settings to host")

			// instantiate a watcher
			log.Infoln("BGP_DIRECTOR: Starting configuration watcher")
			watcher, err := watcher.NewWatcher(ctx, config.KubeConfigFile, config.ConfigMapNamespace, config.ConfigMapName, config.ConfigKey, stats.KindBGPDirector, config.DefaultListener.Service, config.DefaultListener.Port, logger)
			if err != nil {
				return err
			}

			// and Stats for the BGP_DIRECTOR VIPs.
			log.Infoln("BGP_DIRECTOR: creating BGP_DIRECTOR stats")
			s, err := stats.NewStats(ctx, stats.KindBGPDirector, config.Stats.Interface, config.Stats.ListenAddr, config.Stats.ListenPort, config.Stats.Interval, logger)
			if err != nil {
				return fmt.Errorf("failed to initialize metrics. %v", err)
			}
			log.Debugln("BGP_DIRECTOR: checking if BGP_DIRECTOR stats enabled")
			if config.Stats.Enabled {
				if err := s.EnableBPFStats(); err != nil {
					return fmt.Errorf("failed to initialize BPF capture. if=%v sa=%s %v", config.Stats.Interface, config.Stats.ListenAddr, err)
				}
			}

			// emit the version metric
			emitVersionMetric(stats.KindBGPDirector, config.ConfigMapNamespace, config.ConfigMapName, config.ConfigKey)

			/* cmd/ipvsmaster.go does this, but original cmd/director_bgp.go did not. Should this one?
						// Starting up control port.
			            logger.Infof("starting listen controllers on %v", config.Coordinator.Ports)
			            cm := NewCoordinationMetrics(stats.KindIpvsMaster)
			            for _, port := range config.Coordinator.Ports {
			                go listenController(port, cm, logger)
			            }

			            // listen for health
			            logger.Info("starting health endpoint")
			            go util.ListenForHealth(config.Net.Interface, 10201, logger)
			*/

			// instantiate a new IPVS manager
			log.Infoln("BGP_DIRECTOR: Initializing ipvs helper with primary ip:", config.Net.PrimaryIP, "weight override", config.IPVS.WeightOverride, "ignore cordon", config.IPVS.IgnoreCordon)
			ipvs, err := system.NewIPVS(ctx, config.Net.PrimaryIP, config.IPVS.WeightOverride, config.IPVS.IgnoreCordon, logger, stats.KindBGPDirector)
			if err != nil {
				return err
			}

			// instantiate an IP helper for loopback
			log.Infoln("BGP_DIRECTOR: Initializing loopback IP helper")
			ipLoopback, err := system.NewIP(ctx, config.Net.LocalInterface, config.Net.Gateway, config.Arp.LoAnnounce, config.Arp.LoIgnore, logger)
			if err != nil {
				return err
			}
			if err := ipLoopback.SetARP(); err != nil {
				return err
			}

			// instantiate an IP helper for primary interface
			log.Infoln("BGP_DIRECTOR: initializing primary IP helper")
			ipPrimary, err := system.NewIP(ctx, config.Net.Interface, config.Net.Gateway, config.Arp.PrimaryAnnounce, config.Arp.PrimaryIgnore, logger)
			if err != nil {
				return err
			}

			log.Debugln("BGP_DIRECTOR: Setting ARP on primary IP")
			if err := ipPrimary.SetARP(); err != nil {
				return err
			}

			// instantiate BGP_DIRECTOR handler
			log.Infoln("BGP_DIRECTOR: initializing BGP_DIRECTOR helper")
			bgpController := bgp.NewBGPDController(config.BGP.Binary, logger)
			worker, err := bgp.NewBGPWorker(ctx, config.ConfigKey, watcher, ipLoopback, ipPrimary, ipvs, bgpController, config.BGP.Communities, logger)
			if err != nil {
				return err
			}

			log.Debugln("BGP_DIRECTOR: Starting BGP_DIRECTOR worker...")
			err = worker.Start()
			if err != nil {
				return err
			}

			log.Debugln("BGP_DIRECTOR: Waiting for shutdown")

			// catching exit signals sent from the parent context
			<-ctx.Done()
			return worker.Stop()
		},
	}

	return cmd
}
