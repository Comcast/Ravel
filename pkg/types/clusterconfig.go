package types

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

// ClusterConfig is a representation of an input configuration
// for this iptables management utility.
//
// Configuration must support the following use cases:
// - multiple namespaces
// - multiple VIPs
// - multiple namespaces per VIP
// - redundant definitions for the same service (i.e. rio/manifest-agent on 1.2.3.4:8765 and 1.2.3.5:80)
//
// i.e. sharing a single VIP across a pile of namespaces and services,
// all with different (but unique for the VIP) input ports
type ClusterConfig struct {
	VIPPool    []string              `json:"vipPool"`
	MTUConfig  map[ServiceIP]string  `json:"mtuConfig"`
	MTUConfig6 map[ServiceIP]string  `json:"mtuConfig6"`
	NodeLabels map[string]string     `json:"labels"`
	IPV6       map[ServiceIP]string  `json:"ipv6"`
	Config     map[ServiceIP]PortMap `json:"config"`
	Config6    map[ServiceIP]PortMap `json:"config6"`
}

func NewClusterConfig(config *v1.ConfigMap, configKey string) (*ClusterConfig, error) {

	log.Debugln("NewClusterConfig fetching configmap with configKey", configKey)

	clusterConfig := &ClusterConfig{}

	// check for the existence of the requested key.
	if _, ok := config.Data[configKey]; !ok {
		keys := []string{}
		for k := range config.Data {
			keys = append(keys, k)
		}
		return nil, fmt.Errorf("config key '%s' not found in configmap. have '%v'", configKey, keys)
	}

	err := json.Unmarshal([]byte(config.Data[configKey]), &clusterConfig)
	if err != nil {
		return nil, fmt.Errorf("json unmarshal error. %v", err)
	}

	var portConfigCount int
	for ports := range clusterConfig.Config {
		portConfigCount += len(ports)
	}
	log.Debugln("NewClusterConfig: loaded configmap configKey", configKey, "from configmap", config.Name, "with", len(clusterConfig.Config), "IPv4 config entries, and", portConfigCount, "port configs")

	// TODO: validate the cluster config in depth
	if err := clusterConfig.Validate(); err != nil {
		return nil, fmt.Errorf("validation error. %v", err)
	}
	return clusterConfig, nil
}

func (c *ClusterConfig) Validate() error {
	// TODO: add validation!
	return nil
}

// ServiceIP stores a service VIP for iptables and IPVS to manage.
type ServiceIP string

// PortMap stores a mapping of ports to service definitions.
type PortMap map[string]*ServiceDef

// ServiceDef stores a Namespace/Service mapping for input from the
// user, and stores ancillary data collected from iptables about
// the configuration of that service.
type ServiceDef struct {
	Namespace string `json:"namespace"`
	Service   string `json:"service"`
	PortName  string `json:"portName"`

	// Here, the ServiceDef also defines x,y connection limits for IPVS, as well
	// as any other per-LB options
	IPVSOptions IPVSOptions `json:"ipvsOptions"`

	IPV4Enabled          bool `json:"ipv4Enabled"`
	IPV6Enabled          bool `json:"ipv6Enabled"`
	TCPEnabled           bool `json:"tcpEnabled"`
	UDPEnabled           bool `json:"udpEnabled"`
	ProxyProtocolEnabled bool `json:"proxyProtocolEnabled"`
}

// IPVSOptions contains per-service options for the IPVS configuration.
// http://kb.linuxvirtualserver.org/wiki/Ipvsadm
type IPVSOptions struct {

	// For thresholds, while IPVS supports 65536 connections per realserver, the
	// value provided by users will be much larger than this. We take those values
	// and divide them across all the realservers in proportion to the realserver's
	// weight.
	// For instance, if a user provided a value of -x 50000 and -y 25000, and we
	// had 5 realservers each with equal weights -
	//
	//		ipvsadm -A -t 207.175.44.110:80 -s wrr
	//		ipvsadm -a -t 207.175.44.110:80 -r 192.168.10.1:80 -g -x 10000 -y 5000
	//		ipvsadm -a -t 207.175.44.110:80 -r 192.168.10.2:80 -g -x 10000 -y 5000
	//		ipvsadm -a -t 207.175.44.110:80 -r 192.168.10.3:80 -g -x 10000 -y 5000
	//		ipvsadm -a -t 207.175.44.110:80 -r 192.168.10.4:80 -g -x 10000 -y 5000
	//		ipvsadm -a -t 207.175.44.110:80 -r 192.168.10.5:80 -g -x 10000 -y 5000
	//
	// Given those same values for x and y, for 3 realservers with different weights -
	//		ipvsadm -A -t 207.175.44.110:80 -s wrr
	//		ipvsadm -a -t 207.175.44.110:80 -r 192.168.10.1:80 -g -w 2 -x 10000 -y 5000
	//		ipvsadm -a -t 207.175.44.110:80 -r 192.168.10.3:80 -g -w 5 -x 25000 -y 12500
	//		ipvsadm -a -t 207.175.44.110:80 -r 192.168.10.4:80 -g -w 3 -x 15000 -y 7500

	// RawUThreshold is the upper bound beyond which (active+inactive) connections are no longer
	// permitted.
	RawUThreshold int `json:"uThreshold"`
	// RawLThreshold is the lower bound below which active conncections must fall before
	// new connections are accepted.
	RawLThreshold int `json:"lThreshold"`

	// can be either 'g' or 'i', indicating DSR or TUN mode.
	// -g
	RawForwardingMethod string `json:"forwardingMethod"`

	// Scheduler is the way that connections are load balanced to the realservers. defaults to 'wrr'
	// -s wrr
	RawScheduler string `json:"scheduler"`

	// Flags are optional args for a new virtual server
	// if flags: -b <flag-1>,<flag-2>,... (default empty)
	Flags string `json:"flags"`
}

// Scheduler returns a scheduler
func (i *IPVSOptions) Scheduler() string {
	var scheduler string
	switch strings.TrimSpace(strings.ToLower(i.RawScheduler)) {
	case "rr":
		scheduler = "rr"
	case "wrr":
		scheduler = "wrr"
	case "lc":
		scheduler = "lc"
	case "wlc":
		scheduler = "wlc"
	case "dh":
		scheduler = "dh"
	case "sh":
		scheduler = "sh"
	case "mh":
		scheduler = "mh"
	default:
		// not supported:  lblc, lblcr, sed, nq
		if len(i.RawScheduler) > 0 {
			log.Errorln("ipvs: Invalid scheduler specified in IPVSOptions: %s.  Using weighted round robin...", i.RawScheduler)
		}
		scheduler = "wrr"
	}
	return scheduler
}

// UThreshold outputs the upper threshold
func (i *IPVSOptions) UThreshold() int {
	if i.RawLThreshold >= i.RawUThreshold {
		return 0
	} else if i.RawUThreshold < 0 {
		return 0
	}
	return i.RawUThreshold
}

// RawLThreshold outputs the lower threshold
func (i *IPVSOptions) LThreshold() int {
	if i.RawLThreshold >= i.RawUThreshold {
		return 0
	} else if i.RawLThreshold < 0 {
		return 0
	}
	return i.RawLThreshold
}

// ForwardingMethod outupts the forwarding method
func (i *IPVSOptions) ForwardingMethod() string {
	var method string
	switch i.RawForwardingMethod {
	case "g":
		method = "g"
	case "i":
		method = "i"
	default:
		method = "g"
	}
	return method
}

// NewServiceDef accepts a kubernetes-formatted "namespace/service:port" identifier and
// outputs a populated ServiceDef
func NewServiceDef(s string) (*ServiceDef, error) {
	var ns, svc, p string

	tokens := strings.Split(s, "/")
	if len(tokens) != 2 {
		return nil, fmt.Errorf("unable to extract namespace. expected 'namespace/service:portName'. got %s", s)
	}
	ns = tokens[0]
	rest := tokens[1]
	tokens = strings.Split(rest, ":")
	if len(tokens) != 2 {
		return nil, fmt.Errorf("unable to extract service and port. expected 'namespace/service:portName'. got %s", s)
	}

	svc = tokens[0]
	p = tokens[1]

	return &ServiceDef{
		Namespace: ns,
		Service:   svc,
		PortName:  p}, nil
}

/*
package types

import (
	"encoding/json"
	"fmt"

	"github.comcast.com/viper-sde/geronimo/pkg/api"
)

// ClusterConfig is a representation of an input configuration
// for this iptables management utility.
//
// Configuration must support the following use cases:
// - multiple namespaces
// - multiple VIPs
// - multiple namespaces per VIP
// - redundant definitions for the same service (i.e. rio/manifest-agent on 1.2.3.4:8765 and 1.2.3.5:80)
//
// i.e. sharing a single VIP across a pile of namespaces and services,
// all with different (but unique for the VIP) input ports
type ClusterConfig struct {
	VLAN       string                `json:"-"`
	VIPPool    []string              `json:"vipPool"`
	NodeLabels map[string]string     `json:"labels"`
	IPV6       map[ServiceIP]string  `json:"ipv6"`
	Config     map[ServiceIP]PortMap `json:"config"`
	Config6    map[ServiceIP]PortMap `json:"config6"`
}

// AddToVLANFromPost coverts POST request data into a ClusterConfig
func (c ClusterConfig) AddToVLANFromPost(namespace string, service string, portName string, vip string, port string) ClusterConfig {
	serviceDef := &ServiceDef{Namespace: namespace, PortName: portName, Service: service}
	portMap := PortMap{port: serviceDef}
	// Make sure the vip exists
	if _, ok := c.Config[ServiceIP(vip)]; !ok {
		c.Config[ServiceIP(vip)] = PortMap{}
	}
	// Add the new portmap values
	for k, v := range portMap {
		c.Config[ServiceIP(vip)][k] = v
	}

	return c
}

// RemoveFromVLAN coverts POST request data into a ClusterConfig
func (c ClusterConfig) RemoveFromVLAN(vip string, port string) ClusterConfig {
	// Make sure the vip exists
	if _, ok := c.Config[ServiceIP(vip)]; ok {
		// Make sure the port exists
		if _, ok := c.Config[ServiceIP(vip)][port]; ok {
			// If this port is the only port in the configured vip
			if len(c.Config[ServiceIP(vip)]) == 1 {
				// Remove the entire vip from the config
				delete(c.Config, ServiceIP(vip))
			} else {
				// Remove the port from the vip config
				delete(c.Config[ServiceIP(vip)], port)
			}
		}
	}

	return c
}

func NewClusterConfig(config *v1.ConfigMap, configKey string) (*ClusterConfig, error) {
	clusterConfig := &ClusterConfig{}

	// check for the existence of the requested key.
	if _, ok := config.Data[configKey]; !ok {
		keys := []string{}
		for k, _ := range config.Data {
			keys = append(keys, k)
		}
		return clusterConfig, fmt.Errorf("config key '%s' not found in configmap. have '%v'", configKey, keys)
	}

	err := json.Unmarshal([]byte(config.Data[configKey]), &clusterConfig)
	if err != nil {
		return clusterConfig, err
	}

	// Add the VLAN to the clusterConfig
	clusterConfig.VLAN = configKey

	// TODO: validate the cluster config in depth
	return clusterConfig, nil
}

func UpdateConfigMapForVLAN(kube api.KubernetesAPI, vlan string, config *v1.ConfigMap, clusterConfig *ClusterConfig) error {
	b, err := json.Marshal(clusterConfig)
	if err != nil {
		return err
	}
	// Convert bytes to string
	s := string(b[:])
	config.Data[vlan] = s

	//send update existing
	_, err = kube.UpdateExisting(config)
	return err
}

// ServiceIP stores a service VIP for iptables and IPVS to manage.
type ServiceIP string

// PortMap stores a mapping of ports to service definitions.
type PortMap map[string]*ServiceDef

// ServiceDef stores a Namespace/Service mapping for input from the
// user, and stores ancillary data collected from iptables about
// the configuration of that service.
type ServiceDef struct {
	Namespace string `json:"namespace"`
	Service   string `json:"service"`

	PortName string `json:"portName"`
}

// NewDisplayClusterConfig converts a ClusterConfig into a new structure more suitable for display
// The new structure looks like: {Namespace: {Service: {PortName: [VIP:Port]} } }
func NewDisplayClusterConfig(clusterConfig *ClusterConfig) (DisplayClusterConfig, error) {
	displayClusterConfig := DisplayClusterConfig{}
	// First, we iterate over vips and ports to create the frontend service definitions
	for vip, portMap := range clusterConfig.Config {
		for port, serviceDef := range portMap {
			//TODO: Reverse the ServiceDef here
			// Make sure the namespace exists
			if _, ok := displayClusterConfig[serviceDef.Namespace]; !ok {
				displayClusterConfig[serviceDef.Namespace] = DisplayService{}
			}
			serviceConf := ServiceConf{
				Service:  serviceDef.Service,
				VIP:      ServiceIP(vip),
				Port:     port,
				PortName: serviceDef.PortName,
				VLAN:     clusterConfig.VLAN}
			// Add the vip and port under the portname
			displayClusterConfig[serviceDef.Namespace] = append(
				displayClusterConfig[serviceDef.Namespace],
				serviceConf)
		}
	}
	return displayClusterConfig, nil
}

type DisplayConfigs map[string]DisplayClusterConfig

type DisplayClusterConfig map[string]DisplayService

type DisplayService []ServiceConf

type ServiceConf struct {
	Service  string
	VIP      ServiceIP
	Port     string
	PortName string `json:"portName"`
	VLAN     string `json:"-"`
}
*/
