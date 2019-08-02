# firewallnetns chain plugin (not final name, does not work with mesos! they do not support cni spec 0.3.0!)

## Overview

This plugin creates firewall rules only in the network namespace. We created this pluging to apply some simple layer of security to launched tasks. 

**please note: mesos supports only a very old cni network standard. chained plugins are not supported!!**

To do's
- test if we are in a network namespace. If you have host portmapping without a specific network namespace, you will be setting iptables on the host!!
- Implement insert rules (now only appending works)
- Load ipset lists
- Save ipset lists on cmdDel??
- Asked to kill task server / No kill ack received for instance


## Network configuration reference

* `dataDir` (string, optional) Where you store firewall configuration files to be loaded by the plugin.
* `fwFiles` (string, optional) Load and apply these firewall files in the specified order. A file is loaded and applied, before the next one is processed.
* `ipsets` (string, optional) Creates ipsets so they can be referenced in your iptables rules.
* `policies` (string, optional) Sets chain policies.
* `rules` (string, optional) appends iptable rules.

###### firewall files

Firewall files have the same syntax as cni network configuration files but ending on extension .fw. The files can have ipsets, policies and rules.

default-policy.fw

```json
{
  "policies": [
    { "chain": "INPUT", "policy": "DROP" },
    { "chain": "FORWARD", "policy": "DROP" },
    { "chain": "OUTPUT", "policy": "DROP" }
  ]
}
```


## Example (cni command line)

cni chained network configuration file. We use simple macvtap as an interface. Make sure you save it as .conflist not .conf.
(the duplicate useless statements eg. of the policies, are only there to show configuration options)


```json
{
  "cniVersion": "0.3.1",
  "name": "test-firewallnetns",
  "plugins": [
  {
    "type": "macvtap",
    "master": "eth1",
    "ipam": {
      "type": "host-local",
      "subnet": "192.168.124.0/24",
      "rangeStart": "192.168.124.170",
      "rangeEnd": "192.168.124.179"
    }
  },
  {
    "type": "firewallnetns",
    "dataDir": "/etc/mesos-cni",
    "fwFiles": [ "default-policy", "allow-ping", "allow-ping-out" ],
    "ipsets": [
      { "set": "blacklistweb", "hashtype": "hash:ip", "netmask": 24, "hashsize": 4096 }
    ],
    "policies": [
      { "chain": "INPUT", "policy": "ACCEPT" },
      { "chain": "OUTPUT", "policy": "ACCEPT" } ],
    "rules": [
      { "type": "A", "chain": "INPUT", "rule": "-p tcp --dport 8080 -j ACCEPT" },
      { "type": "A", "chain": "INPUT", "rule": "-p tcp --dport 8443 -j ACCEPT" },
      { "type": "A", "chain": "INPUT", "rule": "-p tcp -m set --match-set blacklistweb src -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset" }
      ]
  }
  ]
}
```

When we apply this configuration to the testing network namespace with the cnitool.

`
CNI_PATH="/usr/libexec/cni/" NETCONFPATH="/etc/mesos-cni" cnitool-0.5.2 add test-firewallnetns /var/run/netns/testing
`

We can see the testing namespace has these rules and ipsets

```
[@ ~]# ip netns exec testing iptables -L -vn

Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ACCEPT     icmp --  eth0   *       0.0.0.0/0            0.0.0.0/0            icmptype 8
    0     0 ACCEPT     icmp --  eth0   *       0.0.0.0/0            0.0.0.0/0            icmptype 0
    0     0 ACCEPT     icmp --  eth0   *       0.0.0.0/0            0.0.0.0/0            icmptype 8
    0     0 ACCEPT     icmp --  eth0   *       0.0.0.0/0            0.0.0.0/0            icmptype 0
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8080
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8443
    0     0 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set blacklistweb src multiport dports 80,443 reject-with tcp-reset

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ACCEPT     icmp --  *      eth0    0.0.0.0/0            0.0.0.0/0            icmptype 0
    0     0 ACCEPT     icmp --  *      eth0    0.0.0.0/0            0.0.0.0/0            icmptype 8
    0     0 ACCEPT     icmp --  *      eth0    0.0.0.0/0            0.0.0.0/0            icmptype 0
    0     0 ACCEPT     icmp --  *      eth0    0.0.0.0/0            0.0.0.0/0            icmptype 8

[@ ~]# ip netns exec testing ipset list
Name: blacklistweb
Type: hash:ip
Revision: 4
Header: family inet hashsize 4096 maxelem 65536 netmask 24
Size in memory: 120
References: 1
Number of entries: 0
Members:

```

## Dynamic configuration

Up until now we just applied some static rules to the container. Which does not make sense in a containerized environment. We do not want to create a cni network configuration file for every task.
This is how you can make your cni network configuration files more dynamic so one network configuration can be used for different tasks.


* `use environment variables`<sup id=1>1</sup>
  use environment variables in your iptables rules.
  `{ "type": "A", "chain": "INPUT", "rule": "-p tcp --dport $PORT0 -j ACCEPT" }`

* `use hostnames`
  Say you have 3 instances of a task 'webserver'. The hostname of your task is 'webserver.marathon.mesos'. Then an iptables rule referencing this hostname instead of an ip address, will result in that iptables looks up the 3 ip addresses of the hostname, and adds 3 rules with ip addresses.
  `{ "type": "A", "chain": "INPUT", "rule": "-s webchat.marathon.mesos -j ACCEPT" }`

* `use brute force rules`

* `use ipsetd`
  When using ipset within a container you do not have the ability to append ip addresses/ranges to the list (remember it is only available in the container network namespace). For this reason we have added a process that binds on a tcp port and accepts commands to add or remove entries to an ipset list.
  For example like this:
  `echo  "add blacklistsmtp 12.12.13.12" | ncat webserver.marathon.mesos 9999`
  https://github.com/f1-outsourcing/go-ipset



<b id="f1">1</b> We currently use a forked instance of coreos/go-iptables, with a modification to allow the environment variables to be passed. See issue https://github.com/coreos/go-iptables/pull/67 [↩](#1)


## Use case mesos

** does not work with mesos! because they only support cni spec 0.2.0 of jan 2017, so you will have to wait until they finally fully support 0.3.0 **

The above example is more or less a proof of concept on how to apply 'dynamic' netfilter rules to a network namespace. In practice you will have to deal with the specifics of your container orchestration platform. Things you should consider are not blocking any health checks or executor connections.

Because mesos only supports a very old cni networking standard, I am only able to verify correct iptables rules by applying them to a running instance of a task.

###### marathon task json

We launch this taks via marathon,

```json
{
  "id": "/server",
  "user": "nobody",
  "cpus": 0.1,
  "mem": 32,
  "disk": 0,
  "instances": 1,
  "acceptedResourceRoles": ["*"],
  "backoffSeconds": 10,
  "env": { "IPSET": "1", "IPSET_DEBUG": "1", "IPSET_PORT": "9378" },
  "networks": [ { "mode": "container", "name": "cni-apps" } ],
  "container": {
    "type": "MESOS",
    "docker": {
        "image": "server",
        "credential": null,
        "forcePullImage": true
        },
    "portMappings": [{"containerPort": 8899, "protocol": "tcp"}]
  },
  "healthChecks": [
    {
      "gracePeriodSeconds": 300,
      "intervalSeconds": 30,
      "timeoutSeconds": 5,
      "maxConsecutiveFailures": 3,
      "portIndex": 0,
      "path": "/",
      "protocol": "MESOS_HTTP" 
    }
  ]
}
```

And with these netfilter rules and all policies set to DROP, we keep an operational and healthy task.

```
Chain INPUT (policy DROP 5915 packets, 616K bytes)
 pkts bytes target     prot opt in     out     source               destination
    2   266 ACCEPT     tcp  --  eth0   *       192.168.10.114       0.0.0.0/0            tcp spt:5051
36170 2688K ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
   11  1211 ACCEPT     tcp  --  eth0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8899
    0     0 ACCEPT     tcp  --  eth0   *       192.168.122.22       0.0.0.0/0            tcp dpt:9378

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy DROP 11 packets, 1463 bytes)
 pkts bytes target     prot opt in     out     source               destination
    4  1446 ACCEPT     tcp  --  *      eth0    0.0.0.0/0            192.168.10.114       tcp dpt:5051
36170 2688K ACCEPT     all  --  *      lo      0.0.0.0/0            0.0.0.0/0
   12 18331 ACCEPT     tcp  --  *      eth0    0.0.0.0/0            0.0.0.0/0            tcp spt:8899
    0     0 ACCEPT     tcp  --  *      eth0    0.0.0.0/0            192.168.122.22       tcp spt:9378

```

The executor connection you could allow with something like this

```json
{
  "rules": [
      { "type": "A", "chain": "INPUT", "rule": "-i $CNI_IFNAME -p tcp -s ${MESOS_AGENT_ENDPOINT%%:*} --sport ${MESOS_AGENT_ENDPOINT##*:} -j ACCEPT" },
      { "type": "A", "chain": "OUTPUT", "rule": "-o $CNI_IFNAME -p tcp -d ${MESOS_AGENT_ENDPOINT%%:*} --dport ${MESOS_AGENT_ENDPOINT##*:} -j ACCEPT" }
  ]
}
```

The internal mesos health checks you could allow with something like this

```json
{
  "rules": [
      { "type": "A", "chain": "INPUT", "rule": "-i lo -j ACCEPT" },
      { "type": "A", "chain": "OUTPUT", "rule": "-o lo -j ACCEPT" },
  ]
}
```

The connections to the ipsetd process could be enabled with something like this

```json
{
  "rules": [
      { "type": "A", "chain": "INPUT", "rule": "-i $CNI_IFNAME -p tcp -s 192.168.122.22/32 --dport 9378 -j ACCEPT" },
      { "type": "A", "chain": "OUTPUT", "rule": "-o $CNI_IFNAME -p tcp --sport 9378 -d 192.168.122.22/32 -j ACCEPT" }
  ]
}

```













