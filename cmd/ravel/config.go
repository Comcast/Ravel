package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	ConfigKey          string
	ConfigMapNamespace string
	ConfigMapName      string

	// clean up master conditionally; default true
	CleanupMaster bool

	// PodCIDR omit a pod cidr from masq chain
	PodCIDRMasq  string
	IPTablesMasq bool

	// Periodic reconfigure
	ForcedReconfigure bool

	// This is the IP address of the node - the node as it is known to Kubernetes
	NodeName string

	// This is the location on disk of a kubeconfig
	KubeConfigFile string

	// This is the IPTables prefix to use.
	IPTablesChain string

	// FailoverTimeout is used by the realserver to specify the
	// number of seconds between a loss of the director and the realserver
	// initiating its reconfiguration routine
	FailoverTimeout int

	Stats StatsConfig
	IPVS  IPVSConfig
	Net   NetConfig
	Arp   ArpConfig

	Coordinator CoordinatorConfig

	DefaultListener DefaultListenerConfig

	BGP BGPConfig
}

func (c *Config) Invalid() error {
	if c.IPTablesChain == "" {
		return fmt.Errorf("iptables-chain must be set")
	}
	if c.FailoverTimeout < 1 || c.FailoverTimeout > 120 {
		return fmt.Errorf("failover-timeout must be between 1 and 120s")
	}
	if c.NodeName == "" {
		return fmt.Errorf("nodename must be set. this is the ip address of the node, or its name in kubernetes")
	}
	return nil
}

type DefaultListenerConfig struct {
	Service string
	Port    int
}

type CoordinatorConfig struct {
	// Ports is a list of ports that the director will listen on, the first of which
	// the realserver will populate
	Ports []int
}

func DefaultCoordinatorConfig() CoordinatorConfig {
	return CoordinatorConfig{Ports: []int{44444}}
}

func NewCoordinatorConfig(ports []string) (*CoordinatorConfig, error) {
	c := &CoordinatorConfig{}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no coordinator-ports provided")
	}

	var lastErr error
	intPorts := []int{}
	for _, p := range ports {
		i, err := strconv.Atoi(p)
		if err != nil {
			lastErr = err
			continue
		}
		intPorts = append(intPorts, i)
	}
	c.Ports = intPorts
	return c, lastErr
}

type StatsConfig struct {
	Enabled    bool
	Interface  string
	ListenAddr string
	ListenPort string
	Interval   time.Duration
}

// IPVSConfig if you modify the tags or fields of this struct, or add new ones, run unit tests in config_test.go!!
type IPVSConfig struct {
	// ColocationMode denotes the way that the ipvs director will be configured
	// to deal with pods that are colocated on the same node.
	ColocationMode string

	// Gets set to true by --ipvs-weight-override
	// When true, don't calculate ipvsadm weights, set them to 1 regardless.
	WeightOverride bool

	// Gets set to true by --ipvs-ignore-node-cordon
	// When true, do not evaluate the Cordoned criteria when determining whether a node is an eligible backend
	IgnoreCordon bool

	// Sysctl settings for IPVS.
	SysctlSettings map[string]string
}

// NewIPVSConfig use reflect to pull out defaults we specify in tags
// use reflect to also set the value
// NOTE: the values specified in the systctl parameter must be in the form ipvs_tag_name=<value>
// an error will be returned if not
func NewIPVSConfig(sysctl []string) (*IPVSConfig, error) {
	ipvsConfig := &IPVSConfig{}

	// apply default sysctl settings
	ipvsConfig.SysctlSettings = make(map[string]string)
	ipvsConfig.SysctlSettings["am_droprate"] = "10"
	ipvsConfig.SysctlSettings["amemthresh"] = "1024"
	ipvsConfig.SysctlSettings["backup_only"] = "0"
	ipvsConfig.SysctlSettings["cache_bypass"] = "0"
	ipvsConfig.SysctlSettings["conn_reuse_mode"] = "1"
	ipvsConfig.SysctlSettings["conntrack"] = "0"
	ipvsConfig.SysctlSettings["drop_entry"] = "0"
	ipvsConfig.SysctlSettings["drop_packet"] = "0"
	ipvsConfig.SysctlSettings["expire_nodest_conn"] = "0"
	ipvsConfig.SysctlSettings["expire_quiescent_template"] = "0"
	ipvsConfig.SysctlSettings["ignore_tunneled"] = "1"
	ipvsConfig.SysctlSettings["nat_icmp_send"] = "0"
	ipvsConfig.SysctlSettings["pmtu_disc"] = "1"
	ipvsConfig.SysctlSettings["schedule_icmp"] = "0"
	ipvsConfig.SysctlSettings["secure_tcp"] = "0"
	ipvsConfig.SysctlSettings["sloppy_sctp"] = "0"
	ipvsConfig.SysctlSettings["sloppy_tcp"] = "1"
	ipvsConfig.SysctlSettings["snat_reroute"] = "1"
	ipvsConfig.SysctlSettings["sync_persist_mode"] = "0"
	ipvsConfig.SysctlSettings["sync_ports"] = "1"
	ipvsConfig.SysctlSettings["sync_qlen_max"] = "1028304"
	ipvsConfig.SysctlSettings["sync_refresh_period"] = "0"
	ipvsConfig.SysctlSettings["sync_retries"] = "0"
	ipvsConfig.SysctlSettings["sync_sock_size"] = "0"
	ipvsConfig.SysctlSettings["sync_threshold"] = "3	50"
	ipvsConfig.SysctlSettings["sync_version"] = "1"

	// iterate over supplied ipvs-sysctl settings and override anything already set
	log.Debugln("Parsing specified sysctl settings into sysctl map")
	for _, s := range sysctl {
		spl := strings.Split(s, "=")
		if len(spl) != 2 {
			return ipvsConfig, fmt.Errorf("An incorrectly formatted string was passed from cli. ipvs config flags must be in format --ipvs-sysctl=ipvs_tag_name=<value>")
		}
		name := spl[0]
		value := spl[1]
		log.Debugln("Parsed sysctl setting:", name, value)

		// if the cli user passed in an incorrect name or value
		if name == "" {
			return ipvsConfig, fmt.Errorf("Unable to validate passed sysctl setting with blank name.  The value was: %s", value)
		}
		if value == "" {
			return ipvsConfig, fmt.Errorf("Unable to validate passed sysctl setting with blank value.  The name was: %s", value)
		}

		ipvsConfig.SysctlSettings[name] = value
	}

	return ipvsConfig, nil
}

// GetSysCtlSetting fetches the sysctl setting with the name supplied.  Returns an error if not found.
func (i *IPVSConfig) GetSysCtlSetting(name string) (string, error) {
	value, ok := i.SysctlSettings[name]
	if !ok {
		return "", fmt.Errorf("sysctl setting not found to be set: %s", value)
	}
	return value, nil
}

// WriteToNode writes sysctl settings to the actual node
func (i *IPVSConfig) WriteToNode() error {
	log.Debugln("Writing sysctl settings to node!")
	for name, value := range i.SysctlSettings {
		log.Infoln("setting sysctl value", name, "to", value)
		err := i.SetSysctl(name, value)
		if err != nil {
			log.Debugln("Error when seting sysctl setting", name, value, err)
			return err
		}
	}

	return nil
}

// SetSysctl sets the value of /proc/sys/net/ipv4/vs/<path> to value in config struct
func (i *IPVSConfig) SetSysctl(setting, value string) error {
	// guard against values produced by the struct with no tag
	if setting == "" || value == "" {
		return fmt.Errorf("Unable to set sysctl setting because the setting or value was empty. Setting: %s value: %s", setting, value)
	}
	file := "/proc/sys/net/ipv4/vs/" + setting
	log.Debugln("Setting sysctl", file, "to value:", value)

	f, err := os.OpenFile(file, os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("error opening file at path %s: %v", file, err)
	}
	defer f.Close()

	_, err = f.Write([]byte(value))
	if err != nil {
		return fmt.Errorf("error writing setting %s to %s at path %s: %v", setting, value, file, err)
	}

	log.Debugln("Successfully set sysctl setting", setting, value)
	return nil
}

type NetConfig struct {
	LocalInterface string
	Interface      string
	PrimaryIP      string
	Gateway        string
}

type ArpConfig struct {
	LoAnnounce      int
	LoIgnore        int
	PrimaryAnnounce int
	PrimaryIgnore   int
}

type BGPConfig struct {
	Binary      string
	Communities []string
}

func NewConfig(flags *pflag.FlagSet) *Config {
	config := &Config{}

	config.ConfigMapNamespace = viper.GetString("config-namespace")
	config.ConfigMapName = viper.GetString("config-name")
	config.ConfigKey = viper.GetString("config-key")
	config.NodeName = viper.GetString("nodename")
	config.KubeConfigFile = viper.GetString("kubeconfig")
	config.IPTablesChain = viper.GetString("iptables-chain")
	config.FailoverTimeout = viper.GetInt("failover-timeout")
	config.CleanupMaster = viper.GetBool("cleanup-master")
	config.PodCIDRMasq = viper.GetString("pod-cidr-masq")
	config.IPTablesMasq = viper.GetBool("iptables-masq")
	config.ForcedReconfigure = viper.GetBool("forced-reconfigure")

	if c, err := NewCoordinatorConfig(viper.GetStringSlice("coordinator-port")); err != nil {
		config.Coordinator = DefaultCoordinatorConfig()
	} else {
		config.Coordinator = *c
	}

	config.Net.LocalInterface = viper.GetString("compute-iface-local")
	config.Net.Interface = viper.GetString("compute-iface")
	config.Net.Gateway = viper.GetString("gateway")
	config.Net.PrimaryIP = viper.GetString("primary-ip")

	if i, err := NewIPVSConfig(viper.GetStringSlice("ipvs-sysctl")); err != nil {
		panic(err)
	} else {
		config.IPVS = *i
	}

	config.IPVS.ColocationMode = viper.GetString("ipvs-colocation-mode")
	config.IPVS.WeightOverride = viper.GetBool("ipvs-weight-override")
	config.IPVS.IgnoreCordon = viper.GetBool("ipvs-ignore-node-cordon")

	config.Arp.LoAnnounce = viper.GetInt("lo-announce")
	config.Arp.LoIgnore = viper.GetInt("lo-ignore")
	config.Arp.PrimaryAnnounce = viper.GetInt("primary-announce")
	config.Arp.PrimaryIgnore = viper.GetInt("primary-ignore")

	config.Stats.Enabled = viper.GetBool("stats-enabled")
	config.Stats.Interface = viper.GetString("stats-interface")
	config.Stats.ListenAddr = viper.GetString("stats-listen")
	config.Stats.ListenPort = viper.GetString("stats-port")
	config.Stats.Interval = viper.GetDuration("stats-interval")

	config.DefaultListener.Service = viper.GetString("auto-configure-service")
	config.DefaultListener.Port = viper.GetInt("auto-configure-port")

	config.BGP.Binary = viper.GetString("bgp-bin")
	config.BGP.Communities = viper.GetStringSlice("bgp-communities")

	return config
}
