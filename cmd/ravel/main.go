package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	flagDebug   = true // we cant use the debug flag if we are debugging the flags package now can we?
	flagCfgFile string

	logger *logrus.Logger
	log    logrus.FieldLogger

	logLevel logrus.Level = logrus.InfoLevel
)

var ErrSignalCaught error = fmt.Errorf("caught signal. exiting.")

var allOfTheSignals = []os.Signal{
	os.Signal(syscall.SIGABRT),
	os.Signal(syscall.SIGHUP),
	os.Signal(syscall.SIGINT),
	os.Signal(syscall.SIGKILL),
	os.Signal(syscall.SIGQUIT),
	os.Signal(syscall.SIGSTOP),
	os.Signal(syscall.SIGTERM),
	os.Signal(syscall.SIGUSR1),
	os.Signal(syscall.SIGCONT),
}

func initConfig() error {
	if flagCfgFile != "" {
		viper.SetConfigType("yaml")
		viper.SetConfigFile(flagCfgFile)
		return viper.ReadInConfig()
	}
	return nil
}

func init() {

	logger = logrus.New()
	logger.Formatter = new(logrus.TextFormatter)
	logger.Formatter.(*logrus.TextFormatter).FullTimestamp = true
	logger.SetLevel(logLevel)
	logger.Out = os.Stdout

	// TEMP immediate debugging
	logger.SetLevel(logrus.DebugLevel)
	logger.Debugln("Debug logging enabled!")

	log = logger.WithFields(logrus.Fields{"s": "rdei-lb"})

	cobra.OnInitialize(func() {
		if flagDebug {
			logger.SetLevel(logrus.DebugLevel)
			logger.Debugln("Debug logging enabled!")
		}
		if err := initConfig(); err != nil {
			log.Error(err)
			os.Exit(1)
		}
	})

	rootCmd.PersistentFlags().StringVar(&flagCfgFile, "config", "", "config file")
	rootCmd.PersistentFlags().BoolVar(&flagDebug, "debug", false, "enable debug logging")

	rootCmd.PersistentFlags().String("config-key", "", "The identity of the configuration key that contains the configuration for this kube2ipvs instance in Kubernetes.")
	rootCmd.PersistentFlags().String("config-namespace", "", "The namespace containing the configmap")
	rootCmd.PersistentFlags().String("config-name", "", "The name of the configmap")
	rootCmd.PersistentFlags().String("compute-iface", "", "The name of the desired inbound configKey interface for the director.")
	rootCmd.PersistentFlags().String("compute-iface-local", "lo", "The name of the local interface to use. Defaults to lo. Can also be dummy0")
	rootCmd.PersistentFlags().String("gateway", "", "primary inteface gateway")
	rootCmd.PersistentFlags().String("nodename", "", "required field. the ip address of the node; its identity from kubernetes' standpoint.")
	rootCmd.PersistentFlags().String("kubeconfig", "", "the path to the kubeconfig file containing a crt and key.")
	rootCmd.PersistentFlags().String("primary-ip", "", "The primary IP of the server this is running on.")

	rootCmd.PersistentFlags().Bool("cleanup-master", false, "Cleanup IPVS master on shutdown")
	rootCmd.PersistentFlags().String("pod-cidr-masq", "", "Pod CIDR used to exclude pod network from RDEI-MASQ rules")
	rootCmd.PersistentFlags().Bool("forced-reconfigure", false, "Reconfigure happens every 10 minutes")
	rootCmd.PersistentFlags().Bool("ipvs-weight-override", false, "set all IPVS wrr weights to 1 regardless")
	rootCmd.PersistentFlags().Bool("ipvs-ignore-node-cordon", false, "ignore cordoned flag when determining whether a node is an eligible backend")

	rootCmd.PersistentFlags().String("iptables-chain", "RAVEL", "The name of the iptables chain to use.")
	rootCmd.PersistentFlags().Int("failover-timeout", 1, "number of seconds for the realserver to wait before reconfiguring itself")

	rootCmd.PersistentFlags().Int("lo-announce", 0, "arp_announce setting for loopback interface")
	rootCmd.PersistentFlags().Int("lo-ignore", 0, "arp_ignore setting for loopback interface")
	rootCmd.PersistentFlags().Int("primary-announce", 0, "arp_announce setting for primary interface")
	rootCmd.PersistentFlags().Int("primary-ignore", 0, "arp_ignore setting for primary interface")

	rootCmd.PersistentFlags().String("calico-version", "2", "calico major version. interfaces change between 2 and 3.")
	rootCmd.PersistentFlags().String("calico-dir", "/etc/calico/ravel", "Directory on disk where calico IPPool configurations are written")
	rootCmd.PersistentFlags().String("calico-bin", "/usr/local/bin/calicoctl", "path to calico binary")
	rootCmd.PersistentFlags().String("bgp-bin", "/bin/gobgp", "path to gobgp binary")
	rootCmd.PersistentFlags().Bool("stats-enabled", false, "toggle to enable statistics collection. statistics will be collected from the specified interface device using libpcap. may have a performance implication.")
	rootCmd.PersistentFlags().String("stats-interface", "", "specify the network interface to pcap for stats.")
	rootCmd.PersistentFlags().String("stats-listen", "0.0.0.0", "listen address for prometheus endpoint")
	rootCmd.PersistentFlags().String("stats-port", "10234", "listen port for prometheus endpoint")
	rootCmd.PersistentFlags().Duration("stats-interval", 1*time.Second, "sampling interval")

	rootCmd.PersistentFlags().StringSlice("coordinator-port", []string{"44444"}, "port for the director and realserver to coordinate traffic on. multiple ports supported. if the realserver sees multiple ports, only the first will be used.")
	rootCmd.PersistentFlags().StringSlice("bgp-large-communities", []string{""}, "The large community strings to advertise with BGP announcements.")

	rootCmd.PersistentFlags().String("auto-configure-service", "", "configure the load balancer to send traffic to this service for all vips. must be used in conjunction with auto-configure-port")
	rootCmd.PersistentFlags().Int("auto-configure-port", 0, "vip port to use for autoconfigured monitoring service. ensure that this port does not conflict with configured service ports to prevent conflicts.")
	rootCmd.PersistentFlags().String("ipvs-colocation-mode", "disabled", `Determines colocation mode for IPVS. disabled|iptables|ipvs.
Mode "disabled" means IPVS will not account for colocated pods. Any pods running on the same host as the load balancer will not be addressible through the load balancer.
Mode "iptables" will result in the worker writing iptables rules to capture inbound traffic to local pods.
Mode "ipvs" will result in pod ip addresses being added to the ipvs configuraton. iptables and ipvs modes require the conntrack flag be set.`)
	rootCmd.PersistentFlags().Bool("iptables-masq", true, "determines whether masquerade chain is used in generated iptables rules.")
	viper.BindPFlag("iptables-masq", rootCmd.PersistentFlags().Lookup("iptables-masq"))
	viper.BindPFlag("ipvs-colocation-mode", rootCmd.PersistentFlags().Lookup("ipvs-colocation-mode"))
	viper.BindPFlag("failover-timeout", rootCmd.PersistentFlags().Lookup("failover-timeout"))
	viper.BindPFlag("auto-configure-service", rootCmd.PersistentFlags().Lookup("auto-configure-service"))
	viper.BindPFlag("auto-configure-port", rootCmd.PersistentFlags().Lookup("auto-configure-port"))
	viper.BindPFlag("coordinator-port", rootCmd.PersistentFlags().Lookup("coordinator-port"))
	viper.BindPFlag("stats-enabled", rootCmd.PersistentFlags().Lookup("stats-enabled"))
	viper.BindPFlag("stats-interface", rootCmd.PersistentFlags().Lookup("stats-interface"))
	viper.BindPFlag("stats-listen", rootCmd.PersistentFlags().Lookup("stats-listen"))
	viper.BindPFlag("stats-port", rootCmd.PersistentFlags().Lookup("stats-port"))
	viper.BindPFlag("stats-interval", rootCmd.PersistentFlags().Lookup("stats-interval"))
	viper.BindPFlag("calico-version", rootCmd.PersistentFlags().Lookup("calico-version"))
	viper.BindPFlag("calico-dir", rootCmd.PersistentFlags().Lookup("calico-dir"))
	viper.BindPFlag("calico-bin", rootCmd.PersistentFlags().Lookup("calico-bin"))
	viper.BindPFlag("bgp-bin", rootCmd.PersistentFlags().Lookup("bgp-bin"))
	viper.BindPFlag("config-key", rootCmd.PersistentFlags().Lookup("config-key"))
	viper.BindPFlag("config-namespace", rootCmd.PersistentFlags().Lookup("config-namespace"))
	viper.BindPFlag("config-name", rootCmd.PersistentFlags().Lookup("config-name"))
	viper.BindPFlag("compute-iface", rootCmd.PersistentFlags().Lookup("compute-iface"))
	viper.BindPFlag("compute-iface-local", rootCmd.PersistentFlags().Lookup("compute-iface-local"))
	viper.BindPFlag("gateway", rootCmd.PersistentFlags().Lookup("gateway"))
	viper.BindPFlag("nodename", rootCmd.PersistentFlags().Lookup("nodename"))
	viper.BindPFlag("kubeconfig", rootCmd.PersistentFlags().Lookup("kubeconfig"))
	viper.BindPFlag("primary-ip", rootCmd.PersistentFlags().Lookup("primary-ip"))
	viper.BindPFlag("iptables-chain", rootCmd.PersistentFlags().Lookup("iptables-chain"))
	viper.BindPFlag("lo-announce", rootCmd.PersistentFlags().Lookup("lo-announce"))
	viper.BindPFlag("lo-ignore", rootCmd.PersistentFlags().Lookup("lo-ignore"))
	viper.BindPFlag("primary-announce", rootCmd.PersistentFlags().Lookup("primary-announce"))
	viper.BindPFlag("primary-ignore", rootCmd.PersistentFlags().Lookup("primary-ignore"))
	viper.BindPFlag("cleanup-master", rootCmd.PersistentFlags().Lookup("cleanup-master"))
	viper.BindPFlag("pod-cidr-masq", rootCmd.PersistentFlags().Lookup("pod-cidr-masq"))
	viper.BindPFlag("forced-reconfigure", rootCmd.PersistentFlags().Lookup("forced-reconfigure"))
	viper.BindPFlag("ipvs-weight-override", rootCmd.PersistentFlags().Lookup("ipvs-weight-override"))
	viper.BindPFlag("ipvs-ignore-node-cordon", rootCmd.PersistentFlags().Lookup("ipvs-ignore-node-cordon"))
	viper.BindPFlag("bgp-large-communities", rootCmd.PersistentFlags().Lookup("bgp-large-communities"))
}

func main() {
	log.Infoln("Starting up...")

	// This is he main context that is propagated into the child apps.
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	log.Debugln("Adding commands to rootCmd")
	rootCmd.AddCommand(Director(ctx, log))
	rootCmd.AddCommand(RealServer(ctx, log))
	rootCmd.AddCommand(BGP(ctx, log))
	rootCmd.AddCommand(Version())

	// DEBUG
	log.Infoln("Command arguments:", rootCmd.Flags().Args())

	// Performing a nonblocking run of the application, reading error state through a chan.
	// This allows us to listen for signals at the top level
	errors := make(chan error)
	go func() {
		errors <- rootCmd.Execute()
		log.Debugln("rootCmd.Execute() completed")
	}()

	// signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, allOfTheSignals...)

	exitCode := 0
	log.Debugln("Watching for interrupts")
	select {
	case s := <-sig:
		log.Error("Caught shutdown signal:", s)

		// NOTE: When this cancel functoin is called, the context that was passed
		// into the subcommand at startup will be canceled. This will result in
		// an internal cleanup process kicking off, which should result in the
		// subcommand exiting. So we wait for the subcommand to exit and for
		// its exit value to be passed into the errors chan, which will be read
		// on the next loop iteration.  Note that additional signals may be
		// caught prior to the error being returned. These signals can be safely
		// ignored.
		cancelCtx()

	case err := <-errors:
		if err != nil {
			log.Errorln("rootCmd shutdown with error:", err)
			exitCode = 1
		}
		// This chan is activated when the subcommand exits.
		cancelCtx()
	}

	log.Info("exiting in 1 second")
	<-time.After(1 * time.Second)
	log.Info("exiting with exit code", exitCode)
	os.Exit(exitCode)
}

// This represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:           "kube2ipvs",
	Short:         "kube2ipvs is a cluster load balancer. good luck!",
	Long:          "kube2ipvs is a cluster load balancer. good luck, and have fun!!",
	SilenceUsage:  true,
	SilenceErrors: true,
}
