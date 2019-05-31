
# macvtap/macvlan with routing
work in progress!!!
Here we explain in more detail how communication is established with the container namespace ip address.

## setup the test environment

We use this test environment to illustrate the problem and solution.

```
ifconfig eth0 192.168.10.22

ip link add link eth1 name macvtap1 type macvtap mode bridge
ip link add link eth1 name macvtap2 type macvtap mode bridge
ip link add link eth1 name macvtap3 type macvtap mode bridge

ifconfig macvtap1 up
ifconfig macvtap2 up
ifconfig macvtap3 up

ip link add link eth1 name macvlan1 type macvlan mode bridge
ip link add link eth1 name macvlan2 type macvlan mode bridge
ip link add link eth1 name macvlan3 type macvlan mode bridge

ifconfig macvlan1 up
ifconfig macvlan2 up
ifconfig macvlan3 up

ip netns add testingmacvtap
ip netns add testingmacvlan

ip link set macvtap3 netns testingmacvtap
ip link set macvlan3 netns testingmacvlan

```

## the problem when assigning a different ip address from the host


Our host runs with the ip address 192.168.10.22 on the interface eth0. We want our tasks to run on a different lan connected to eth1 (with no ip address assigned).
Lets now assign our namespaces with an ip address from 192.168.122.0 range.

```
ip netns exec testingmacvtap ifconfig macvtap3 192.168.122.33 up
```

From our host environment we can of course ping the local hosts ip.

```
[root@test2 ~]# ping -c 3 192.168.10.22
PING 192.168.10.22 (192.168.10.22) 56(84) bytes of data.
64 bytes from 192.168.10.22: icmp_seq=1 ttl=64 time=0.015 ms
64 bytes from 192.168.10.22: icmp_seq=2 ttl=64 time=0.020 ms
64 bytes from 192.168.10.22: icmp_seq=3 ttl=64 time=0.015 ms

--- 192.168.10.22 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1999ms
rtt min/avg/max/mdev = 0.015/0.016/0.020/0.005 ms
[root@test2 ~]#
```

If we try to ping from the namespace to the hosts ip we get of course a Network unreachable error message. So we have to add a route within the namespace telling how to contact the hosts ip (this route you can specify in the ipam routes section).

```
ip netns exec testingmacvtap route add 192.168.10.22/32 dev macvtap3
```

If we now try to ping the hosts ip from the namespace we do not get a Network unreachable error. But we also do not get a reply. This is because the host does not know how to contact the ip address within the namespace.

So lets tell the host how to contact the namespace ip. For this, we just route<sup id=2>2</sup> this specific ip traffic through a macvtap interface still available on the host, which you can specify in "hostrouteif" configuration of the cni plugin. We have to remember that macvtap/macvlan interfaces cannot communicate with their hosts.
The ip address for the route, that is being used we get from the ipam plugin returned.

```
ip route add 192.168.122.33/32 dev macvtap1
```

If we now do a ping from the network namespace, we get a reply. So this basically solves to problem with communicating to the mesos agent/slave running with a different ip on the host.

```
[root@test2 ~]# ip netns exec testingmacvtap ping -c 3 192.168.10.22
PING 192.168.10.22 (192.168.10.22) 56(84) bytes of data.
64 bytes from 192.168.10.22: icmp_seq=1 ttl=64 time=0.394 ms
64 bytes from 192.168.10.22: icmp_seq=2 ttl=64 time=0.023 ms
64 bytes from 192.168.10.22: icmp_seq=3 ttl=64 time=0.033 ms

--- 192.168.10.22 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2000ms
rtt min/avg/max/mdev = 0.023/0.150/0.394/0.172 ms
[root@test2 ~]#
```

## Use case

We have a set of hosts that do not have direct access to the internet. They have gretap tunnels that are connected to a router which is allowing internet access.
Currently qemu/kvm vms are connected via macvtap on the tunnel device to the internet. These vm's can be live migrated between hosts keeping their client connections.

Because it is just a small setup we want to keep things simple, we are not using openvswitch for networking, and we also want to limit the amount of packages we install or daemons we are running on the hosts.

Having this setup, we were looking at the possiblities of running tasks (mongodb,mariadb etc) alongside these vm's, so preferably we would like to launch the tasks with the macvtap device<sup id=1>1</sup>.

###### The hosts

Hosts have all a tunnel device tun1 which is connected to the router. Vm's on the hosts can all reach each other via the network on the tunnel.

```
  +---+------+---+    +---+------+---+   +---+------+---+
  |   | eth0 |   |    |   | eth0 |   |   |   | eth0 |   |
  |   +------+   |    |   +------+   |   |   +------+   |
  |              |    |              |   |              |
  |     HOST     |    |     HOST     |   |     HOST     |
  |              |    |              |   |              |
  |   +------+   |    |   +------+   |   |   +------+   |
  |   | tun1 |   |    |   | tun1 |   |   |   | tun1 |   |
  +---+------+---+    +---+------+---+   +---+------+---+
```


###### A host

Most vm's do not need to have access to the 192.168.10 range. The ones that do, are put on a macvtap connected to that network.
The vm's on the tunnel can either have an internal range 192.168.122 that can be natted to the internet and is filtered on the router. Or they can be assigned a public internet address (which is routed via the same tunnel without restrictions)

Putting tasks/apps (with dedicated ip) on the tunnel with mesos requires some sort of connection with eth0 to which the mesos slave is bound. Connecting the tasks/apps to the tunnel, allows us to either give them internet access, or just allow access from the internal 192.168.122 lan for use with the vm's.

```
 +-------+---+------+----------------+-----------------+
 | HOSTA |   | eth0 |  macvtap       |                 |
 |       |   +------+  192.168.10.20 |                 |
 |       +-----------------+---------+                 |
 |           .             |                           |
 |           .             |                           |
 |           .             |                           |
 |       +------+       +------+  +------+  +------+   |
 |       |      |       |10.23 |  |      |  |      |   |
 |       | app  |       |  VM  |  |  VM  |  |  VM  |   |
 |       |122.31|       |122.23|  |122.22|  |122.21|   |
 |       +--+---+       +--+---+  +--+---+  +--+---+   |
 |          |              |         |         |       |
 |          |              |         |         |       |
 |          |              |         |         |       |
 |        +-+--------------+---------+---------+-+     |
 |        | macvtap     +------+                 |     |
 |        |             | tun1 |                 |     |
 +--------+-------------+------+-----------------+-----+

```



<b id="f1">1</b> I was testing with the macvlan interface but something was not working there, can't remember what exactly.[↩](#1)
<b id="f1">2</b> When testing we noticed that if the host has a device configured with an ip address from the same range of the tasks/vms, routing table preferences give problems. One solution would be to give our route a higher preference.[↩](#1)