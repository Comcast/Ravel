

## Release 2.3.1


### Features

- IPIP tunneling supports load balancing across subnet boundaries
- Director supports traffic shaping to colocated pods - support for isolated and colocated modes of operation
- Director tested to 700k packets per second in isolated mode, 450k packets per second in colocated mode.  (peak @ Rogers 350k pps)
- Realserver supports traffic pinning to node. Inbound sessions no longer leave the realserver through kube-proxy
- Client IP addresses preserved.
- Implementation supports dynamic configuration of upper and lower connection limit thresholds (feature gated via rdei api)


### Functional Changes

- The load balancer no longer supports transit of service to backends that are not specified in the nodeLabels configuration.  In practical terms, this closes a security hole and prevents the use of an "origin" load balancer to send traffic to pods running in a "green" security zone.

### Known Issues

- Accessing cluster VIPs from within the same security zone is not supported


### Details

**VPES-1620 - Kube-Proxy bugfix - removing KUBE-MARK-DROP duplication**

Kube-proxy has a defect where it creates duplicate packet marking rules in
the kube-mark-drop chain. Ravel is in a good position to correct this issue
by deduplicating the contents of that chain when it generates a new iptables
configuration.


**VPES-1619 - Director supports traffic shaping to colocated pods**

The traffic pinning solution implemented in VPES-1393 is not suitable for clusters
where the IPVS director is colocated with application workloads. In order to
support load balancing of traffic to containers running on the same node as the
director, the director will now create a set of iptables rules for the local
pods with a statistical rule to accept connections in proportion to the number
of pods in the service that are running on the director.

In order to support this, `proc/sys/net/ipv4/vs/conntrack` must be set to `1`.
Ravel now supports setting any value for any `vs` sysctl setting via a command-line
flag.


**VPES-1393 - Traffic pinning support for inbound traffic**

In the prior configuration, traffic landing on a node
would be injected into iptables rules belonging to kube-proxy. This configuration
suffered from two major drawbacks. First, kube-proxy is a random NAT, and using
it means that most traffic for a service is redirected to pods running on a
different node. Second, in Kubernetes 1.11, the behavior of kube-proxy changed
in a way that resulted in iptables corruption and an internal deadlock.

In order to address this, the ipvs director now applies weights to realservers
in accordance with the relative number of pods running on each realserver. This,
in conjunction with a `wrr` scheduler, means that each realserver will receive
traffic in proportion to the number of pods running on that realserver. Second,
the realserver itself now has generated RAVEL- iptables rules that are specific
to the pods running on that server. The jump to kube-proxy is no longer a factor,
and the integration with kube-proxy has been deprecated entirely.

To support this change, ipvs rules are now incrementally applied and weights are
changed instantaneously whenever the Kubernetes API reports a change to endpoint
status.



**VPES-1462 - IP Tunneling support for realserver + Concurrency fix for director**

* Added flag to switch local interface.

This allows for a dummy device to be used instead of loopback,
which is a requirement for ip tunneling. (according to the guide).

* Added rp_filter settings for realserver

* Fixed bug in watcher for nodes.

The nodes watch was appending whenever an ADDED directive was
found. This resulted in a disconnect from the api server amplifying
the total number of nodes.

Now, the ADDED command checks to ensure that the node isn't already
present in the list, and if found, it updates it.

* Replacing v1.Node with types.Node

In order to prepare the director to receive more information from
kubernetes, we are transitioning away from the builtin nodes type
towards a purpose-built type that will contain the subset of data
that we need for this exercise.

* fixed defects in watcher

- nodes were not being added to the list for the added event type

* Fixed watch/worker interactions for IPVS master

The IPVS master was doing a bunch of stuff in its control loop, and
that work was blocking reads from the watcher's input channels.
Now, the master receives its configurations and performs work in
separate goroutines.

- watches goroutine - reads from watcher
- arps goroutine - does periodic arping calls
- periodic goroutine - checks for updated configs every 100ms

One downside to this approach is that each respective goroutine
has a duplicated section to stop work when the contexts are
canceled.


**VPES-1417 - Implemented support for X,Y and other IPVS opts**

The ClusterConfig has been updated to optionally specify an
IPVSOptions dictionary that contains settings for X, Y, Forwarding
Mode, and Scheduler.

Invalid settings are never rejected - we always configure a load
balancer - but they will be normalized to a version of the settings
that is correct. In particular, the set of valid forwarding modes
and schedulers is hard-coded in a switch statement, where user
input is the switch, but the output is our own values.

For X and Y settings, validation is done in the ClusterConfig
to ensure that X is greater than Y and greater than zero, with
additional validation in the IPVS worker to reject settings that
exceed the IPVS per-realserver limit of 65536 connections per
realserver.

In addition, the publish command in the ipvs watcher has been
debounced - so multiple successive updates applied in a short
timeframe will be grouped into a single update to the worker
thread. Note that the implementation here will nearly always result
in the max timeout being met, as changes to endpoints are nearly
continuous.


**VPES-1410 - Removed shutdown cleanup from director**

When the director shuts down, it will now leave its prior configuration
intact. This helps to ensure that transient restarts of the service
do not result in a loss of VIP connectivity.


**VPES-1411 - Added realserver cleanup timeout and tests**

A command line flag can now be set to specify the amount of time that will
elapse between the director going offline and the realserver coming online.



**VPES-1279 Watcher needs to exclude services that have no endpoints**

In kube 1.10, a feature was added to the iptables proxier to remove service records
that did not have endpoints associated with them. This resulted in the kube-proxy
iptables-restore command failing when Ravel was holding onto an association with
the newly-deleted rule.



## Release 2.1.0
---

**VPES-1231 Support for multiple director coordination ports. (#25)**

The director and realserver coordinate through the use of a listen port that
the director opens up. The realserver then tests this port periodically and uses
 its presence as a marker that the director is running.

This change implements support for multiple listen ports on the director side,
so that we can migrate away from the ephemeral port range in a way that is
backwards compatible with running systems.

On the director, multiple `--coordinator-port` arguments can be passed in. The
director will open a listener on each of these ports, and exit the program if
any listeners fail.

On the realserver, multiple `--coordinator-port` arguments can be passed, but
only the first argument will be used.  

If the argument is not passed or is invalid, the value will default to 44444.


**VPES-1134 - Fixed cleanup on shutdown / status transfer (#24)**

- listening for SIGCONT which is required in rkt environments in order to
ensure that the app doesn't get sigkilled
- logging for initialization as well as for cleanup
- reconfiguration check added to bgp, realserver, and director
- cleanup blocks until periodic tasks complete, or 5s elapse
- iptables chain provided at the command line, defaults to RAVEL
- cleanup process catches all errors as it progresses, instead of bailing on
the first
- BGP workflow restored in periodic configuration


**VPES-1186 RDEI creates its own masq chain for inbound traffic (#21)**

This avoids possible collisions around the KUBE-MARK-MASQ chain.


**VPES-1133 - Added check to prevent reconfiguration race. (#20)**

The IPVS worker has been modified to set a 'reconfiguring' variable when either
the Start or Stop commands are run. This variable is checked when the commands
start and is reset in a deferred function. If it's true, a call to either Start
or Stop will fail. In the case of the master/backend detection, this will
prevent multiple successive calls from completing before the start or stop
command has fully exited.


**VPES-1136 Added error checking for watch reset (#19)**

Previously, if the watch connection failed for any reason, all
watches would just deadlock and fail forever. Now, the watch
will reset and exponentially backoff to a 30-second wait before
reestablishing the watch.

In addition, a metric is emitted that indicates the backoff duration.
This can be used to detect issues with the API from the load balancer's
perspective

**VPES-1154 ClusterIP=None bugfix (#18)**

Two bugfixes:

Ravel crashed the whole cluster if a service was configured with ClusterIP=None.
Ravel's exponential backoff did not kick in until the 5-minute duration was
reached.


**Added config filtering back into watcher**

This was previously removed in favor of using the iptables preventative, but
that approach alone resulted in a conflict with kube-proxy.

the load balancer would only remove services from the listing if
the iptables rules weren't present. this resulted in a case where
an iptables rule in the rdei-lb chain would be referencing a rule
that kube-proxy wanted to remove. when kube-proxy failed to remove
the rule, the iptables configuration would become stale.

this change introduces a check in the watcher to remove services
that don't have any endpoints. in addition, new infromation is returned
from iptables indicating the number of rules removed from the chain
prior to application. this helps to ensure that if a rule is removed
from itpables, the load balancer has a chance to add it back if
it's racing with kube-proxy.


**Added option for autoconfigured service.**

This is a service that will automatically be configured on the
target port for every vip in the vip pool. This can be used to
ensure that all IP addressed provided to the load balancer are
routable on the network and respond to network requests, helping
to ensure that the IPAM team doesn't reclaim then for another
purpose. It can also be used to rapidly determine the health of
the load balancer, in the small, by addressing a request to any
and all VIPs on this management port.



**added cleanup for high-cardinality metrics**

The Reset() method on the metrics emitter is called to clear out
all configuration changes, etc. This may also reset counters, which may
necessitate an alternative approach to communicating current config.

**Added deep instrumentation into the runtime state of the load balancer.**

- LB emits version information
- iptables emits a bunch of metrics
- watcher emits a bunch of metrics
- bgp worker emits metrics
- director and realserver workers emit metrics

**metrics proof of concept**

- metrics are now invoked earlier in all the subcommands
- metrics server is _always_ started, with bpf/pcap metrics now conditional
- metrics are invoked at the start of a command; this is for injection into
places
- switched container image over to alpine

**command re-integration**

- BGP mode integrated with Kube2IPVS
