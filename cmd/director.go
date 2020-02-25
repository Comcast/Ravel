package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/comcast/ravel/pkg/director"
	"github.com/comcast/ravel/pkg/iptables"
	"github.com/comcast/ravel/pkg/stats"
	"github.com/comcast/ravel/pkg/system"
	"github.com/comcast/ravel/pkg/types"
	"github.com/comcast/ravel/pkg/util"
)

// Director runs the ipvs Director
func Director(ctx context.Context, logger logrus.FieldLogger) *cobra.Command {

	var cmd = &cobra.Command{
		Use:           "director",
		Short:         "kube2ipvs director",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `
kube2ipvs director will run the kube2ipvs daemon in director mode,
where it will continuously check the kubernetes API for updates to both
node heath as well as the client port configuration.

In director mode, kube2ipvs will directly interact with ipvsadm in order
to delete rules that exist, but no longer apply, and to create rules that
are missing from the configuration.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			config := NewConfig(cmd.Flags())
			logger.Debugf("got config %+v", config)
			b, _ := json.MarshalIndent(config, " ", " ")
			fmt.Println(string(b))

			// validate flags
			logger.Info("validating")
			if err := config.Invalid(); err != nil {
				return err
			}

			// write IPVS Sysctl flags to director node
			if err := config.IPVS.WriteToNode(); err != nil {
				return err
			}

			// instantiate a watcher
			logger.Info("starting watcher")
			watcher, err := system.NewWatcher(ctx, config.KubeConfigFile, config.ConfigMapNamespace, config.ConfigMapName, config.ConfigKey, stats.KindDirector, config.DefaultListener.Service, config.DefaultListener.Port, logger)
			if err != nil {
				return err
			}

			// initialize statistics
			s, err := stats.NewStats(ctx, stats.KindDirector, config.Stats.Interface, config.Stats.ListenAddr, config.Stats.ListenPort, config.Stats.Interval, logger)
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
			emitVersionMetric(stats.KindDirector, config.ConfigMapNamespace, config.ConfigMapName, config.ConfigKey)

			// Starting up control port.
			logger.Infof("starting listen controllers on %v", config.Coordinator.Ports)
			cm := NewCoordinationMetrics(stats.KindDirector)
			for _, port := range config.Coordinator.Ports {
				go listenController(port, cm, logger)
			}

			// listen for health
			logger.Info("starting health endpoint")
			go util.ListenForHealth(config.Net.Interface, 10201, logger)

			// instantiate a new IPVS manager
			logger.Info("initializing ipvs helper")
			ipvs, err := system.NewIPVS(ctx, config.Net.PrimaryIP, config.IPVS.WeightOverride, config.IPVS.IgnoreCordon, logger)
			if err != nil {
				return err
			}

			// instantiate an IP helper for loopback and set the arp rules
			// the loopback helper only runs once, at startup
			logger.Info("initializing loopback ip helper")
			ipLoopback, err := system.NewIP(ctx, "lo", config.Net.Gateway, config.Arp.LoAnnounce, config.Arp.LoIgnore, logger)
			if err != nil {
				return err
			}
			if err := ipLoopback.SetARP(); err != nil {
				return err
			}

			// instantiate a new IP helper
			logger.Info("initializing primary ip helper")
			ip, err := system.NewIP(ctx, config.Net.Interface, config.Net.Gateway, config.Arp.PrimaryAnnounce, config.Arp.PrimaryIgnore, logger)
			if err != nil {
				return err
			}

			// instantiate an iptables interface
			logger.Info("initializing iptables")
			ipt, err := iptables.NewIPTables(ctx, stats.KindDirector, config.ConfigKey, config.PodCIDRMasq, config.IPTablesChain, config.IPTablesMasq, logger)
			if err != nil {
				return err
			}

			// instantiate the director worker.
			logger.Info("initializing director")
			worker, err := director.NewDirector(ctx, config.NodeName, config.ConfigKey, config.CleanupMaster, watcher, ipvs, ip, ipt, config.IPVS.ColocationMode, config.ForcedReconfigure, logger)
			if err != nil {
				return err
			}

			// start the director
			logger.Info("starting worker")
			err = worker.Start()
			if err != nil {
				return err
			}
			logger.Info("started")
			for { // ever
				select {
				case <-ctx.Done():
					// catching exit signals sent from the parent context
					// Removed in VPES-1410. When director exits, we shouldn't clean nup!
					// return worker.Stop()
				}
			}
		},
	}

	cmd.Flags().StringSlice("ipvs-sysctl", []string{""}, "sysctl setting for ipvs. can be passed multiple times. '--ipvs-sysctl=conntrack=0 --ipvs-sysctl=ignore_tunneled=0'")
	viper.BindPFlag("ipvs-sysctl", cmd.Flags().Lookup("ipvs-sysctl"))

	return cmd
}
