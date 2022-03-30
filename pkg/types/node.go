package types

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

const (
	v6AddrLabelKey = "rdei.io/node-addr-v6"
)

// NodesEqual returns a boolean value indicating whether the contents of the
// two passed NodesLists are equivalent.
func NodesEqual(a []Node, b []Node, logger logrus.FieldLogger) bool {
	return reflect.DeepEqual(a, b)
}

// NodeEqual returns a boolean value indicating whether two nodes are EQUAL
func NodeEqual(a, b Node) bool {
	return reflect.DeepEqual(a, b)
}

// NodesList is a sortable array of nodes.
type NodesList []Node

func (n NodesList) Len() int           { return len(n) }
func (n NodesList) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }
func (n NodesList) Less(i, j int) bool { return n[i].Name < n[j].Name }

func (n NodesList) Copy() NodesList {
	out := make(NodesList, len(n))
	copy(out, n)
	// for i, node := range n {
	// 	out[i] = node
	// }
	return out
}

// The Node represents the subset of information about a kube node that is
// relevant for the configuration of the ipvs load balancer. Upon instantiation
// it only contains the set of information retrieved from a kube node.  Its
// AddEndpointsForConfig([]v1.Endpoints, *clusterConfig) function will add kube
// endpoints in, filtering on the basis of whether they're associated with that
// particular node.
type Node struct {
	Name          string            `json:"name"`
	Addresses     []string          `json:"addresses"`
	Unschedulable bool              `json:"unschedulable"`
	Ready         bool              `json:"ready"`
	Labels        map[string]string `json:"labels"`

	// an internal type used to extract the v6 address from a nodelabel, set by a boot process
	AddressV6 string

	addressTotals map[string]int
	localTotals   map[string]int

	EndpointAddresses []v1.EndpointAddress `json:"endpoints"`
}

// GetLocalServicePropability computes the likelihood that any traffic for the
// service ends up on this particular node.
func (n *Node) GetLocalServicePropability(namespace, service, portName string, logger logrus.FieldLogger) float64 {
	ident := MakeIdent(namespace, service, portName)
	// logger.Infof("WAT local=%v total=%v", n.localTotals, n.addressTotals)
	if tot, ok := n.addressTotals[ident]; !ok || tot == 0 {
		return 0.0
	} else if _, ok := n.localTotals[ident]; !ok {
		return 0.0
	}
	return float64(n.localTotals[ident]) / float64(n.addressTotals[ident])
}

func NewNode(kubeNode *v1.Node) Node {
	n := Node{}
	n.Name = kubeNode.Name
	n.Addresses = addresses(kubeNode)
	n.Unschedulable = kubeNode.Spec.Unschedulable
	n.Ready = isInReadyState(kubeNode)
	n.Labels = kubeNode.GetLabels()

	n.EndpointAddresses = []v1.EndpointAddress{}
	return n
}

func (n *Node) IPV4() string {
	for _, addr := range n.Addresses {
		i := net.ParseIP(addr)
		if i.To4() != nil {
			return i.String()
		}
	}
	return ""
}

func (n *Node) IPV6() string {
	if v6Addr, ok := n.Labels[v6AddrLabelKey]; ok {
		return strings.Replace(v6Addr, "-", ":", -1)
	}
	return ""
}

func (n *Node) IsEligibleBackendV4(labels map[string]string, ignoreCordon bool) (bool, string) {
	return n.IsEligibleBackend(labels, ignoreCordon, false)
}

func (n *Node) IsEligibleBackendV6(labels map[string]string, ignoreCordon bool) (bool, string) {
	return n.IsEligibleBackend(labels, ignoreCordon, true)
}

func (n *Node) IsEligibleBackend(labels map[string]string, ignoreCordon bool, v6 bool) (bool, string) {
	if len(n.Addresses) == 0 {
		return false, fmt.Sprintf("node %s does not have an IP address", n.Name)
	}

	if n.Unschedulable && !ignoreCordon {
		return false, fmt.Sprintf("node %s has unschedulable set. saw %v", n.IPV4(), n.Unschedulable)
	}

	if !n.Ready {
		return false, fmt.Sprintf("node %s is not in a ready state.", n.IPV4())
	}

	if !n.hasLabels(labels) {
		return false, fmt.Sprintf("node %s missing required labels: want: '%v'. saw: '%v'", n.IPV4(), labels, n.Labels)
	}

	return true, fmt.Sprintf("node %s is eligible", n.IPV4())
}

// hasLabels returns true if the set of labels on the Node contains the key/value pairs expressed in the input, l
func (n *Node) hasLabels(l map[string]string) bool {
	for wantKey, wantValue := range l {
		if hasValue, ok := n.Labels[wantKey]; !ok || hasValue != wantValue {
			return false
		}
	}
	return true
}

func isInReadyState(n *v1.Node) bool {
	isReady := false
	for _, c := range n.Status.Conditions {
		if c.Type != "Ready" {
			continue
		}
		if c.Status == "True" {
			isReady = true
		}
	}
	return isReady
}

func addresses(n *v1.Node) []string {
	out := []string{}
	for _, addr := range n.Status.Addresses {
		if addr.Type == "InternalIP" && addr.Address != "" {
			out = append(out, addr.Address)
		}
	}
	return out
}

type Port struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type Ports []Port

func (p Ports) Len() int           { return len(p) }
func (p Ports) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p Ports) Less(i, j int) bool { return len(p[i].Name) < len(p[j].Name) }

// MakeIdent standardizes a string construction used in packages nodes and watcher
func MakeIdent(namespace, service, portName string) string {
	ident := namespace + "/" + service + ":" + portName
	return ident
}
