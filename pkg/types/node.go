package types

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	v1 "k8s.io/api/core/v1"
)

const (
	v6AddrLabelKey = "rdei.io/node-addr-v6"
)

// NodesEqual returns a boolean value indicating whether the contents of the
// two passed NodesLists are equivalent.
func NodesEqual(a []*v1.Node, b []*v1.Node) bool {
	return reflect.DeepEqual(a, b)
}

// NodeEqual returns a boolean value indicating whether two nodes are EQUAL
func NodeEqual(a, b *v1.Node) bool {
	return reflect.DeepEqual(a, b)
}

// NodesList is a sortable array of nodes.
// type NodesList []Node

// func (n NodesList) Len() int           { return len(n) }
// func (n NodesList) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }
// func (n NodesList) Less(i, j int) bool { return n[i].Name < n[j].Name }

// func (n NodesList) Copy() NodesList {
// 	out := make(NodesList, len(n))
// 	copy(out, n)
// 	// for i, node := range n {
// 	// 	out[i] = node
// 	// }
// 	return out
// }

// The Node represents the subset of information about a kube node that is
// relevant for the configuration of the ipvs load balancer. Upon instantiation
// it only contains the set of information retrieved from a kube node.  Its
// AddEndpointsForConfig([]v1.Endpoints, *clusterConfig) function will add kube
// endpoints in, filtering on the basis of whether they're associated with that
// particular node.
// type Node struct {
// Name          string            `json:"name"`
// Addresses     []string          `json:"addresses"`
// Unschedulable bool              `json:"unschedulable"`
// Ready         bool              `json:"ready"`
// Labels        map[string]string `json:"labels"`

// an internal type used to extract the v6 address from a nodelabel, set by a boot process
// AddressV6 string

// addressTotals map[string]int
// localTotals   map[string]int

// EndpointAddresses []v1.EndpointAddress `json:"endpoints"`
// }

// func NewNode(kubeNode *v1.Node) Node {
// 	n := Node{}
// 	n.Name = kubeNode.Name
// 	n.Addresses = addresses(kubeNode)
// 	n.Unschedulable = kubeNode.Spec.Unschedulable
// 	n.Ready = isInReadyState(kubeNode)
// 	n.Labels = kubeNode.GetLabels()

// 	// n.EndpointAddresses = []v1.EndpointAddress{}
// 	return n
// }

func IPV4(n *v1.Node) string {
	for _, addr := range n.Status.Addresses {
		i := net.ParseIP(addr.Address)
		if i.To4() != nil {
			return i.String()
		}
	}
	return ""
}

func IPV6(n *v1.Node) string {
	if v6Addr, ok := n.Labels[v6AddrLabelKey]; ok {
		return strings.Replace(v6Addr, "-", ":", -1)
	}
	return ""
}

func IsEligibleBackendV4(n *v1.Node, labels map[string]string, ip string, ignoreCordon bool, skipMasterNode bool) (bool, string) {
	return IsEligibleBackend(n, labels, ip, ignoreCordon, false, skipMasterNode)
}

func IsEligibleBackendV6(n *v1.Node, labels map[string]string, ip string, ignoreCordon bool, skipMasterNode bool) (bool, string) {
	return IsEligibleBackend(n, labels, ip, ignoreCordon, true, skipMasterNode)
}

func IsEligibleBackend(n *v1.Node, labels map[string]string, ip string, ignoreCordon bool, v6 bool, skipMasterNode bool) (bool, string) {
	if len(n.Status.Addresses) == 0 {
		return false, fmt.Sprintf("node %s does not have an IP address", n.Name)
	}

	if IsUnschedulable(n) && !ignoreCordon {
		return false, fmt.Sprintf("node %s has unschedulable taint set.", n.Name)
	}

	if !IsInReadyState(n) {
		return false, fmt.Sprintf("node %s is not in a ready state.", n.Name)
	}

	if !hasLabels(n, labels) {
		return false, fmt.Sprintf("node %s missing required labels: want: '%v'. saw: '%v'", n.Name, labels, n.Labels)
	}
	if skipMasterNode { // 2.5 behavior where master nodes are skipped
		if !v6 && IPV4(n) == ip {
			return false, fmt.Sprintf("node %s matches ip address %s",IPV4(n), ip)
		}
	}

	return true, fmt.Sprintf("node %s is eligible", n.Name)
}

// hasLabels returns true if the set of labels on the Node contains the key/value pairs expressed in the input, l
func hasLabels(n *v1.Node, l map[string]string) bool {
	for wantKey, wantValue := range l {
		if hasValue, ok := n.Labels[wantKey]; !ok || hasValue != wantValue {
			return false
		}
	}
	return true
}

func IsUnschedulable(n *v1.Node) bool {
	for _, c := range n.Spec.Taints {
		if c.Key == v1.TaintNodeUnschedulable {
			return true
		}
	}
	return false
}

func IsInReadyState(n *v1.Node) bool {
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

func Addresses(n *v1.Node) []string {
	out := []string{}
	for _, addr := range n.Status.Addresses {
		if addr.Type == "InternalIP" && addr.Address != "" {
			out = append(out, addr.Address)
		}
	}
	return out
}

// type Port struct {
// 	Name     string `json:"name"`
// 	Port     int    `json:"port"`
// 	Protocol string `json:"protocol"`
// }

// type Ports []Port

// func (p Ports) Len() int           { return len(p) }
// func (p Ports) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
// func (p Ports) Less(i, j int) bool { return len(p[i].Name) < len(p[j].Name) }

// MakeIdent standardizes a string construction used in packages nodes and watcher
func MakeIdent(namespace, service, portName string) string {
	ident := namespace + "/" + service + ":" + portName
	return ident
}
