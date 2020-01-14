# TROUBLESHOOTING KUBE2IPVS

Kube2IPVS is a complex application. It retrieves information from two sources
in the Kubernetes API and marries those sources together to create both IPVS
configuration settings and iptables settings.
Malfunctions and bugs only show up as problems reaching pods.

Your best first check is to do: `curl http://$VIP:70` to see if the "Unicorns"
pod is up and getting packets via $VIP.
The load balancer director routes packets to the "Unicorns" process over all VIPs.
If that doesn't work, it's time for other checks.

1. Is the director running? Is the director working properly?
2. Is packet attraction (ARP or BGP) working?
3. Is the realserver (on each compute node) working? Is it working properly?

## IPVS trouble

These commands will only be worthwhile on the machine running a director.
That's the machine that runs a `rkt` pod for the older ARP-based director,
and it's a dedicated machine for the new BGP-based director.

* `lsmod` - show modules in the kernel. "ip_vs", "ip_vs_wrr", "ip_vs_rr", "ip_vs_sh"
are the IPVS modules. 
* `top` is the only place you can see the work of distributing packets/connections
having an effect. The "id" (system idle) and "si" (software interrupt) percentages
can go from 99/0 (id/si) to 60/30 under super heavy load balancing.
The kernel does all the work, so no process gets billed for it.
* `sudo rkt list | grep ravel` - which `rkt` pod is running ravel, what version of ravel
* `sudo systemctl status ravel-director` - what `systemd` thinks is going on
* `sudo ipvsadm-save -n` - list all the IPVS rules. Remember, these can be in place
even if the load balancer director process dies, or is hung or something.
* `sudo ipvsadm -l -n -c` - list all the ongoing TCP connections going through IPVS
* `sudo ipvsadm -l --timeout` - show the TCP state timeouts.
"tcpfin", which defaults to 120 seconds, is how long a connection is kept in FIN_WAIT state.
Connections pile up in FIN_WAIT state, since IPVS machines only see half a TCP connection
tear down, and can only wait for a timeout if they are to be standards-conformant.
* `watch "cat /proc/net/ip_vs_conn | awk 'NR>1{print \$8}' | sort | uniq -c | sort -k2.1"`
will show you a near-real-time count of IPVS connections' TCP states.
FIN_WAIT state counts do tend to make people nervous.

There are some sysctl type things.
Look at `/proc/net/ip_vs*` - these are mostly informative.
I think `ipvsadm-save` is a slight reformatting of `cat /proc/sys/net/ip_vs`.
The config sysctl things are in `/proc/sys/net/ipv4/vs`.
The only one that it seems like it might be worth setting/resetting is `/proc/sys/net/ipv4/conntrack`.
Except that it doesn't seem to have any effect.
I've run ARP-based load balancer directors with a "1" value,
and BGP-based load balancer directors with a "0" value.
It worked both ways,
possibly because something else is turning on `nf_conntrack`.
On the other hand, I don't see how IPVS can work at all without at least a simple
form of connection tracking.
Once a TCP-3-way-handshake completes,
IPVS passes data segments of that TCP connection to the same realserver every time.

IPVS rules should be identical across all BGP-tier (machines running BGP-based directors)
machines.
It's best to collect the rules with a shell script:

    for IP in 10.131.153.72 10.131.153.73 10.131.153.74
    do
        ssh $IP 'sudo ipvsadm-save -n' > $IP.ipvs.rules
    done

You can diff the IPVS rules at your leisure,
but at least you collected them at almost the same time.

You can use the `ipvsadm` command to edit weights, remove compute nodes from a virtual server,
etc, but `kube2ipvs bgp` or `kube2ipvs director` will put everything back the way it thinks
things should be the next time it receives a configmap from kubernetes.

### Running out of sockets/running out of ports

TCP stacks assign an "ephemeral port number" to any sockets that a client opens.
Different OSes use different ranges.
IPVS doesn't use ports per se on the director machines,
but if a client program or programs open and close a lot of connections to a load-balanced
VIP:port, it's possible for the client machine to run out of ephemeral ports.
There's a hard-coded 60 second wait before the Linux kernel will re-use the port number.
Should some programmer with a poorly-coded client implementation get after the load balancer
for using up ports, it's possible to alleviate that a little bit, albeit by stepping out
of the bounds of playing it safe. On Linux:

    sudo sysctl net.ipv4.tcp_tw_reuse=1
    sudo sysctl net.ipv4.ip_local_port_range='20000 60999'

That will make the ephemeral port range larger than the default,
and it will let the client's Linux kernel re-use any TIME_WAIT sockets' port numbers.
This probably won't help for long, but it might encourage someone to think they've tried
everything, and thus need a re-design.

It's barely within the realm of possibility, but the director's machine,
the machine routing packets using IPVS,
could conceivably run out of some kind of resource if it was handling a
very large number of on-going TCP connections,
or if it was under heavy load by something that rapidly opened and closed TCP connections.
I'm not sure what the proximal indication of this would be, even.
You can find web pages that refer to `nf_conntrack: table full, dropping packet`
messages, but I was not able to ever trigger these.
The size of the conntrack table is apparently compiled in to the kernel or the IPVS modules,
so you can't bump up a parameter to get a larger table.
You can change the IPVS "tcpfin" timeout so that (from IPVS' point of view) half-closed
sockets in FIN_WAIT state don't need to be tracked for very long.

    sudo ipvsadm --set $(sudo ipvsadm -l --timeout | awk '{print $5, 10, $7}')

That will set the "tcpfin" timeout to 10 seconds, leaving the other two mysterious values alone.

## BGP Trouble

These commands will only be worthwhile on the machine running a BGP director,
which will not be a compute node of a cluster.
That machine will also run a `gobgpd` pod.

`gobgpd` isn't all that complicated.
Your best bet is to just `sudo systemctl restart gobgpd` once you determine it's the problem.
This will withdraw any routes to VIPs, causing on-going TCP connections to drop.
But it takes less than 30 seconds for `systemctl` to stop the pod, and restart it,
then have it connect to top-of-rack-routers.

`gobgpd` config file lives in the BGP director's regular filesystem,
so you can look at it and edit it from the usual command line, without entering a pod.
Conveniently, it's named `/etc/gobgpd.conf`.
There's not a lot in it, "router-id", "as" and "neighbor-address" values are important.
The "neighor-address" values are the IP addresses of the top-of-rack-routers.
These aren't the same as the "default" route IP address you get from `ip -br r`.
That default is a VIP maintained by the two top-of-rack-routers.
Each of them has another IP address of its own, and that's the value of "neighbor-address".
It's a [TOML](https://github.com/toml-lang/toml) file, so watch indentation.

* `sudo rkt list | grep gobgpd` - which `rkt` pod is running `gobgpd`, what version of `gobgpd`
* `sudo systemctl status gobgpd` - what `systemd` thinks is going on
* `sudo journalctl -u gobgpd` - what `gobpgd` has logged, which isn't typically a lot.
`msg="Peer Up" Key=10.131.153.67 State=BGP_FSM_OPENCONFIRM Topic=Peer`
is about the message to see to ensure that `gobgpd` has made a peer of the top-of-rack-router.
* `sudo lsof -p $(ps -e | grep gobgpd | awk '{print $1}')` shows you what file descriptors
`gobgpd` has open, which should include a TCP socket, "bgp" or port 50051.

From here it gets a little murkier. You have to have a `gobgp` executable to contact
the `gobgpd` daemon process.

1. Get in the pod: `sudo rkt enter $(sudo rkt list | grep gobgpd | awk '{print $1}') /bin/sh`
2. Inside the pod, `gobgp n` shows you the "neighbors", the status of the top-of-rack-routers
3. `gobgp n 10.131.153.66` (or whatever the router's IP address) shows you more than you want.
Look for `BGP state = ESTABLISHED, up for 19d 01:21:05` if you're making sure it's talking
to the top-of-rack router.
4. `gobgp n 10.131.153.66 adj-out` should show you the VIPs for that cluster,
and where the top-of-rack-router thinks it should send them, which is the IP address
of the load balancer director machine the `gobgpd` pod runs on.
5. `/bin/gobgp global  rib -a ipv4 del 10.54.213.148/32` - get `gobgpd` to withdraw a route.
6. `/bin/gobgp global  rib -a ipv4 add 10.54.213.148/32` - get `gobgpd` to add a route.

The `gobgp` executable is also inside the `ravel` pod, you can use it from inside there.

I'm pretty sure that if you monkey with BGP routes, `kube2ipvs bgp` will never change them
back, unlike for IPVS rules.

## ARP configuration

The ARP configuration of even a BGP-based director's machine is important.
See [ARP issues in LVS/DR and LVS/TUN Clusters](http://kb.linuxvirtualserver.org/wiki/ARP_Issues_in_LVS/DR_and_LVS/TUN_Clusters).
The upshot is that we don't want realserver machines responding to ARP "who-has" questions
for VIPs.
If they do, there's a small possibility that the top-of-rack router will decide to put the
MAC address of the realserver machine into its table matching the VIP to a single machine's
MAC address.
This machine isn't running IPVS rules that let it route packets from VIP:port to other
machines, so all the VIP traffic goes to that single compute node's pods.

* `cat /proc/sys/net/ipv4/conf/lo/arp_ignore` should say "1"
* `cat /proc/sys/net/ipv4/conf/lo/arp_announce` should say "2"
* `cat /proc/sys/net/ipv4/conf/po0/arp_ignore` should say "1"
* `cat /proc/sys/net/ipv4/conf/po0/arp_announce` should say "2"

You can check if ARPs are getting issued with:

    tcpdump -n -i po0 arp

Look for "is-at" packets with VIPs as the IP address.
"Who-has" ARP requests should not be answered by any MAC address, really,
but especially not one of the compute server MAC addresses.

As of Oct 2019, Comcast used Arista top-of-rack-routers.
It seems like any BGP routes override any IP addresses the routers learn via ARP,
so I'm not sure this is a real problem. It probably depends heavily on brand and configuration
of the top-of-rack-routers.

### ARP packet attraction

The ARP-based director shells out to `/usr/bin/arping`. The command looks like this:

    /usr/sbin/arping -c 1 -s $VIP_IP $gateway_ip -I $interface

The effect is to with the director-machine's bridged interface MAC address along with a VIP,
ask for the "default" route's IP address.
This causes the top-of-rack-routers, who between them keep up the default route VIP,
to keep the director machine's MAC address matched with the VIPs.

Supposedly every 2 seconds a goroutine in the ARP-based director shells out to `arping` like that.
`/usr/sbin/arping` is an executable inside the director's pod.
It's a "busybox" implementation.
It waits for 1 second after the first "is-at" ARP reply for any further replies.
These never happen, but it takes 1+ seconds for the "busybox" implementation to time out.
A cluster that has N VIPs will take not 2 seconds, but at least N seconds to send out
gratuitous ARPs for all the VIPs.
That sounds OK, every VIP gets a gratuitous ARP every N seconds.
Except that the director program keeps all the VIPs in a Golang map.
When doing a "range" over key/value pairs of a map is not really random,
it's just not the same each time.
It turns out that some VIPs get picked first a lot more than other VIPs.
Usually, but not always some VIP is the last one in the "range".
Very occasionally, it will be the first one chosen to gratuitously ARP.
Together with a larger number of VIPs, say 50, every onece in a while a very long
interval between gratuitous ARPs for a particular VIP occurs.
Supposedly, Arista top-of-rack routers have a 2-hour timeout on ARP table entries,
so even if a 5 minute or so interval between gratuitous ARPs happens,
a TOR shouldn't time-out a VIP ARP table entry.
But it's worth considering.

## TCP Resets

This is relevant to a BGP-based load balancer with multiple directors.

TCP packets with the "reset" (RST) flag set can be indicative of problems,
problems with the top-of-rack-routers.
There's a complicated relationship between "leaf" routers and top-of-rack router,
with each of 2 leafs connected to each of 2 TORs, for a total of 4 connections.
It's possibly for the leaf routers to decide to drop a connection with one of the 2 TORs.
The leaf router will send any packets arriving after the connection drop to the other
TOR. That TOR will decide to send packets to any directors that have advertised routes
to the VIP in question.
Any packets that get sent to a director machine not originally doing one of the re-routed
connections will trigger a RST packet from that director's Linux kernel.

Prometheus metrics have counts of FIN, RST and SYN,ACK packets for each service/VIP.
A pulse of RST packets could indicate a problem in the leaf router(s) or in the connections
between leaf an TOR.
A long-term increase in RST packets probably means something wrong with the top-of-rack-routers:
they're not consistently sending connections to the same director process.

You can use `tcpdump` to watch for this kind of RST packet like this:

    sudo tcpdump -n -i po0  'src host 10.131.153.125 and (tcp[tcpflags] & (tcp-rst) != 0)'

It is possible for ARP-based directors to incur RST packets as well,
but they appear to be spontaneously generated.
After a short (4 - 30 second) idle period of a long running TCP connection,
the next data segment from the client earns a RST from the director machine's kernel.
This appears to happen on compute nodes that run the director and a realserver.
The director puts in `iptables` rules, too, one of them puts a "mark" on packets
that cause the rest of the `iptables` rules to do "SNAT", source network address translation,
putting VIP:port as the source address.
But it does not put in a SNAT rule.
The mark ends up using Calico-originated rules to actually send the packet for SNAT.
Calico-originated rules use the same mark bit, for the same purpose.
My theory is that whatever connection tracking IPVS uses, and whatever connection tracking
Calico rules end up loading "race" to decide what to do with a packet.
Most of the time, the IPVS conntrack wins. Everything works.
Some of the time, Calico-rules-induced-conntrack wins, and a RST gets generated.
Get rid of the realserver, or at least the presence of pods that cause the realserver
to put iptables rules in place, and these spontaneously-generated RST packets don't happen.

# Basic Kubernetes Troubleshooting

## Retrieving a list of all of the actual configurations

for host in $(curl -s http://10.43.150.97:8080/api/v1/nodes | jq .items[].spec.externalID | sed 's/"//g' | grep 150); do echo -n $host " "; ssh $host "sudo iptables -t nat -S KUBE-IPVS | wc -l"; done

## kube2ipvs logs:
https://splunk-cdvr.idk.cable.comcast.com/en-US/app/search/search?display.page.search.mode=smart&q=search%20sourcetype%3Dkube2ipvs%20app%3Dmaster%20flushing&earliest=-2d&latest=now&sid=1471108207.140041\

## Config map:
http://10.43.150.97:8080/api/v1/namespaces/platform-load-balancer/configmaps

## Master configs:
ssh 10.43.150.109 docker -H unix:///var/run/early-docker.sock exec ipvs-master-green.service ipvsadm

## Ipvs units:
fleetctl --endpoint=http://10.43.150.101:2379 list-units  | grep ipvs

## Twin nodes:
fleetctl --endpoint=http://10.43.150.101:2379 list-machines

# Troubleshooting Features

Kube2IPVS would benefit from the following troubleshooting features:

1. run it in Kubernetes so that HTTP endpoints can be created to access Kube2IPVS health and data
2. a Kube2IPVS command that generates the cardinal set of rules for ipvsadm and iptables
3. a Kube2IPVS command that publishes the config map
4. a Kube2IPVS command that accesses all nodes on a cluster and retrieves generated configurations from http endpoints
