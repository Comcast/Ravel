# Ravel Cluster Load Balancer

![Ravel Logo](ravel_logo.png?raw=true)

Ravel is a high-performance cluster load balancer for bare-metal deployments of Kubernetes. It supports L2 direct-server-reply load balancing using LVS, as well as L3 load balancing through a BGP integration with GoBGP.

Ravel features include:

- Dynamically updating configuration
- Multiple persistent VIP addresses
- Shared VIP addresses across multiple services
- High availability with sub-millisecond failover
- IPV4, TCP load balancing
- Direct traffic injection to Kubernetes service chains
- Direct reply mode for cluster-width egress bandwidth
- Semantic configuration via configmap
- Port forwarding
- Operational metrics
- Per-VIP usage Statistics
- Default service configurations for unclaimed VIP addresses
- In-cluster load balancing. No separate tier required
- Automatic removal of Unschedulable or NotReady nodes from backends
- Automatic updates to inbound load balancing rules in response to Configmap changes
- Clean up on exit

Coming soon for Ravel:

- IPV6 support
- Kubernetes LoadBalancer controller support


## Architecture

The general idea is to make a set of kubernetes pods that can all do the same work
look like they're a single, very powerful machine,
by getting the rest of the world to see a single IP address (a Virtual IP address, a "VIP")
that can be used to access any of the pods.
Kubernetes has services that programmers can use to group the pods by the work they do.
Because there's a limited number of IP addresses, RDEI assigns each service a port in the VIP.
There's not enough IP addresses to provide every service with its own exclusive VIP.
You'd also still need to assign a TCP port number.
This drives the balancing to be done with a VIP:port per load balanced service.

A load balancer has to respond to 2 sets of dynamic inputs:

1. Respond to kubernetes changes - A set of VIPs, pods moving, services appearing and disappearing.
2. Respond to RDEI - kubernetes services gettting matched to a virtual IP address (VIP) and port number.

The ultimate goal is getting packets to their desired destination,
a pod that can do the work.

This particular load balancer has 3 tasks that it has to do to respond to inputs,
and obtain its goal.

1. Get packets arriving from a load balanced VIP:port to a pod that matches.
Kubernetes pod and service information is the key piece here,
along with what VIP:port matches what service.
2. Get packets from the rest of the world arriving with a load balanced VIP:port
to a compute node that's running a pod or pods in the service that matches that VIP:port.
VIP:port to service, from RDEI, compute node and which services and pods run on compute nodes
from kubernetes API are the key inputs.
3. Tell a router that some machine(s) can and should receive packets and TCP connections
for particular VIPs. This falls out of the other two requirements,
and the way Internet Protocol is routed.

We did this with 2 levels or tiers,
one that directs traffic from VIP:port to a compute node that runs appropriate pods,
and one tier that gets packets from VIP:port to an appropriate pod on the same machine.
The firsts level is a "director", the second is a "realserver", borrowing terminology
from the IPVS project.


### Attract Packets and connections

This load balancer has two "directors", one that can use ARP to tell the top-of-rack-router
that its machine can receive packets for a list of IP addresses (the VIPs),
and one that uses a subsidiary BGP daemon ([gobgpd](https://osrg.github.io/gobgp/))
to tell the top-of-rack-router what VIPs can be received.

The advantage of using ARP is its simplicity.
ARP is traditionally how a router figures out which MAC address matches a destination IP address.
ARP is a simple, well-known protocol with user level APIs and administrative utilities.
The director process can issue gratuitous ARPs easily without extra configuration.

The disadvantage of using ARP to tell a router which VIPs can be handled, is that by design, 
ARP matches 1 MAC address to 1 IP address. There is really no way to have "multi-headed" load
balancers using ARP to attract packets. A secondary disadvantage is that the load balancer director
machine has to be on the same subnet as the top-of-rack-router, and so do VIPs.
Since ARP uses MAC broadcast addresses, the director machine has to be in the same broadcast
domain as the top-of-rack router.

Using Border Gateway Protocol (BGP) also has pros and cons.
BGP is a complicated protocol.
It needs a process/thread to continually tell the router it's alive,
and the connection is up.
It requires more configuration,
like what's the IP address of the router and what Address Space the VIP is in,
and maybe even more,
if you want to do graceful shutdown,
and graceful restart.

Using BGP to attact packets has advantages.
The machine(s) don't have to be in the same subnet or broadcast domain as the VIPs or the router.
A director could possibly run in an adjacent rack.
VIPs can be arbitrary, instead of having to be in the same subnet as the IP addresses of the compute nodes.

More than one machine can be a director:
BGP doesn't make a strict association between 1 IP address and 1 MAC address.
Using BGP means that multiple director machines can work in parallel.
This gives us much less distruptive fail-over.
Rather than having to detect that a single gratuitiously-ARP-ing machine has failed,
and either needs to be restarted,
or the service moved elsewhere,
some fraction of ongoing TCP connections fail, the top-of-rack router adjusts its connection hashing,
and the other director machine(s) get more connections.

The value relative to the ARP-based director, is horizontal scaling.
The cost is another pod running `gobpgd`,
some extra config files and command line options,
and the extra knowledge to [administer and debug](TROUBLESHOOTING.md) `gobgdp`.

### Get packets arriving from anywhere to a compute node

This load balancer uses [IPVS](http://www.linuxvirtualserver.org/software/ipvs.html)
to distribute packets to compute nodes.
The program is a "director", either ARP or BGP based packet attracting
(`rkt` container running `kube2ipvs director` or `kube2ipvs bgp` respectively).
The compute nodes that are routed-to should run pod(s) that are members of a service matched to a VIP:port in RDEI.
Both the ARP-using and BPG-using directors calculate IPVS rules based on what kubernetes API
tells them is the list of nodes in the cluster, the pods running in the cluster,
what service the pods are in, and the VIP:port that matches a given service from RDEI.
The IPVS rules receive packets from a VIP:port, send them to the IP address of a compute node.

The director process creates/deletes/edits IPVS rules.
The Linux kernel follows the rules,
routing the packets and tracking the connections.
The director process can exit, the Linux kernel will keep routing the packets & etc.
The director process exec's an `ipvsadm` process to either create or delete rules
that make the kernel route VIP:port to various compute node IP addresses.
The code goes to great effort to not have small intervals where no rules are in place:
it either deletes or adds rules, and it edits rules where the "weight"
(derived from number of pods running on a machine) might have changed.

### Get packets arriving from a VIP:port to a pod

Finally, the last step: getting packets with a VIP:port source address to a pod that
can handle them.
Every compute node in a RDEI kubernetes cluster has a "realserver" process running on it.
That's a `rkt` container running `kube2ipvs realserver`.
This particular pod listens to Kubernetes API for pods and endpoints, and to RDEI for VIPs, ports and services.
It combines information from them so that it can write `iptables` rules
that send packets from a VIP:port to a pod that can handle the packets.
Information from RDEI determines if a pod can "handle" packets from a VIP:port.
This gets complicated because the compute nodes also run [Calico](https://docs.projectcalico.org/v2.0/getting-started/kubernetes/),
which sets up inscrutable `iptables` rules to allow intra-cluster communication
on 192.168.x.y addresses.
The `iptables` rules that the realserver sets up direct packets from a VIP:port to a pod's IP address,
a 192.168.a.b address assigned by Kuberenetes (or maybe Docker) when the pod starts.

The realserver does the same sort of work as a director does,
except it does iptables rules, not IPVS rules.
It only adds or deletes rules,
never leaving an interval where no `iptables` rules exist.
On a machine with more than a single pod for a load balanced service,
the realserver adds a probability so that multiple packets on a node get their fair share of
connections, if not actual CPU-consuming load.
If the pod count on a compute node changes, these probabilities get re-calculated.
Finally, the rules realservers generate a rule
that ends up using the Calico rule for "SNAT", "Source Network Address Translation".
This sets the *source* IP address and port of any packets returning from pod to client,
to the VIP:port being load balanced.
MAC address remains that of the compute node.
The compute node sends packets returning to clients directly to them - Direct Server Return.
This makes the return bandwidth from pods to any clients calling on them a boost:
any data returned does not have to return through the director's IPVS system.
Since most client requests are small amounts of bytes relative to the returned data,
the system works.
<!-- -A RAVEL-MASQ -j MARK --set-xmark 0x4000/0x4000 -->

## Statistics

The RDEI Load Balancer emits metrics about its internal state and optionally emits metrics about the traffic that is being load balanced for each configured VIP.


```
    # HELP rdei_lb_channel_depth is a gauge denoting the number of inbound clusterconfig objects in the configchan. a value greater than 1 indicates a potential slowdown or deadlock
    # TYPE rdei_lb_channel_depth gauge
    rdei_lb_channel_depth{lb="realserver",seczone="green-786-10.54.213.128_25"} 0

    --

    # HELP rdei_lb_cluster_config_info contains the current cluster config and a sha has of the config
    # TYPE rdei_lb_cluster_config_info gauge
    rdei_lb_cluster_config_info{date="2019-02-15T00:11:40Z",info="<current-config>",lb="realserver",seczone="green-786-10.54.213.128_25",sha="PcBJZC0Xt/PH+HUFyK0SPQecQuA="} 1

    --

    # HELP rdei_lb_flows_count a counter to measure the increase in active tcp and udp connections
    # TYPE rdei_lb_flows_count counter
    rdei_lb_flows_count{lb="realserver",namespace="cadieuxtest1",port="8012",port_name="http",protocol="TCP",service="nginx",vip="10.54.213.247"} 0

    --

    # HELP rdei_lb_info version information for rdei lb
    # TYPE rdei_lb_info gauge
    rdei_lb_info{arch="linux/amd64",buildDate="2019-02-14T23:57:47Z",commit="a7f58c20ae765ca07bcaa0d7a32158c068702799",configName="kube2ipvs",configNamespace="platform-load-balancer",goVersion="go1.11.2",lb="realserver",seczone="green-786-10.54.213.128_25",startTime="2019-02-15T00:11:43Z",version="0.0.0"} 0

    --

    # HELP rdei_lb_iptables_chain_size is twi guages, one for the inbound/calculated chain size, and one for the configured size.
    # TYPE rdei_lb_iptables_chain_size gauge
    rdei_lb_iptables_chain_size{kind="applied",lb="bgp",seczone="green-786-10.54.213.128_25"} 26

    --

    # HELP rdei_lb_iptables_latency_microseconds is a histogram denoting the amount of time it takes to perform various iptables operations. labels for operation save|restore|flush and for outcome error|success
    # TYPE rdei_lb_iptables_latency_microseconds histogram
    rdei_lb_iptables_latency_microseconds_bucket{attempts="0",lb="bgp",operation="flush",outcome="success",seczone="green-786-10.54.213.128_25",le="100"} 0

    --

    # HELP rdei_lb_iptables_operation_count is a count of operations performed against iptables and the status
    # TYPE rdei_lb_iptables_operation_count counter
    rdei_lb_iptables_operation_count{attempts="0",lb="bgp",operation="flush",outcome="success",seczone="green-786-10.54.213.128_25"} 2

    --

    # HELP rdei_lb_reconfigure_count is a count of reconfiguration events with labels denoting a success|error|noop
    # TYPE rdei_lb_reconfigure_count counter
    rdei_lb_reconfigure_count{lb="realserver",outcome="complete",seczone="green-786-10.54.213.128_25"} 1

    --

    # HELP rdei_lb_reconfigure_latency_microseconds is a histogram denoting the amount of time an end-to-end reconfiguration took, split out by labels on the outcome.
    # TYPE rdei_lb_reconfigure_latency_microseconds histogram
    rdei_lb_reconfigure_latency_microseconds_bucket{lb="realserver",outcome="complete",seczone="green-786-10.54.213.128_25",le="100"} 0

    --

    # HELP rdei_lb_rx_bytes a counter to measure the bytes received
    # TYPE rdei_lb_rx_bytes counter
    rdei_lb_rx_bytes{lb="realserver",namespace="cadieuxtest1",port="8012",port_name="http",protocol="TCP",service="nginx",vip="10.54.213.247"} 0

    --

    # HELP rdei_lb_tcp_state_count A counter variable that measures protocol, port name, namespace, service, state events like rst or synack, and counts for respective event types
    # TYPE rdei_lb_tcp_state_count counter
    rdei_lb_tcp_state_count{lb="realserver",namespace="cadieuxtest1",port="8012",port_name="http",protocol="TCP",service="nginx",state_event="fin",vip="10.54.213.247"} 0

    --

    # HELP rdei_lb_tx_bytes a counter to measure the bytes transmitted
    # TYPE rdei_lb_tx_bytes counter
    rdei_lb_tx_bytes{lb="realserver",namespace="cadieuxtest1",port="8012",port_name="http",protocol="TCP",service="nginx",vip="10.54.213.247"} 0

    --

    # HELP rdei_lb_watch_backoff_duration returns the current value of the watch backoff duration. a non-1s duration indicates that the backoff is present and the load balancer is unable to communicate with the api server
    # TYPE rdei_lb_watch_backoff_duration gauge
    rdei_lb_watch_backoff_duration{lb="realserver",seczone="green-786-10.54.213.128_25"} 1

    --

    # HELP rdei_lb_watch_cluster_config_count is a count of how often a cluster config is regenerated, broken out by event - noop|publis|error
    # TYPE rdei_lb_watch_cluster_config_count counter
    rdei_lb_watch_cluster_config_count{event="noop",lb="realserver",seczone="green-786-10.54.213.128_25"} 108553

    --

    # HELP rdei_lb_watch_data_count is a count of data inbound from the kuberntes watch events, broken out by endpoint
    # TYPE rdei_lb_watch_data_count counter
    rdei_lb_watch_data_count{endpoint="configmaps",lb="realserver",seczone="green-786-10.54.213.128_25"} 88

    --

    # HELP rdei_lb_watch_init_count is a count of watch init events.
    # TYPE rdei_lb_watch_init_count counter
    rdei_lb_watch_init_count{lb="realserver",seczone="green-786-10.54.213.128_25"} 27

    --

    # HELP rdei_lb_watch_init_latency_microseconds is a histogram denoting the amount of time it took to reestablish all of the watches
    # TYPE rdei_lb_watch_init_latency_microseconds histogram
    rdei_lb_watch_init_latency_microseconds_bucket{lb="realserver",seczone="green-786-10.54.213.128_25",le="100"} 0

```



## TODOS:

- rename the stats-enable flag to stats-pcap-enable
- add validation for the various subcommands
