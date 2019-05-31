# macvtap plugin

## Overview

[macvtap](http://backreference.org/2014/03/20/some-notes-on-macvlanmacvtap/) functions like a switch that is already connected to the host interface.
A host interface gets "enslaved" with the virtual interfaces sharing the physical device but having distinct MAC addresses.
Since each macvtap interface has its own MAC address, it makes it easy to use with existing DHCP servers already present on the network.

## Example configuration

```
{
  "name": "test-macvtap",
  "type": "macvtap",
  "master": "eth1",
  "hostrouteif": "macvtap1",
  "ipam": {
    "type": "host-local",
    "subnet": "192.168.122.0/24",
    "rangeStart": "192.168.122.171",
    "rangeEnd": "192.168.122.179",
    "routes": [ { "dst": "192.168.122.22/32", "gw": "0.0.0.0" },
                { "dst": "192.168.10.22/32", "gw": "0.0.0.0" }]
  },
  "dns": { "nameservers": ["192.168.10.10"] },
  "args": {
    "cni": { "ips": ["192.168.122.177"] }
  }
}

```

## Network configuration reference

* `name` (string, required): the name of the network
* `type` (string, required): "macvlan"
* `master` (string, optional): name of the host interface to enslave. Defaults to default route interace.
* `hostrouteif` (string, optional): name of the host interface to route via.
* `mode` (string, optional): one of "bridge", "private", "vepa", "passthru". Defaults to "bridge".
* `mtu` (integer, optional): explicitly set MTU to the specified value. Defaults to the value chosen by the kernel.
* `ipam` (dictionary, required): IPAM configuration to be used for this network. For interface only without ip address, create empty dictionary.

## hostrouteif
The hostrouteif option we added to be able to communicate with the host. When tasks are launched, the host agent needs to be able to communicatie with the task. This is not a problem if tasks are in the same ip range of the slave/agent. For instance if you use the bridge plugin this communication is via the hosts bridge ip. If you would remove the gateway ip address of the bridge, your task would not launch. Simply because it cannot communicate with the host.

When using the hostrouteif
- A host route is created upon task launch (that will tell the host how to reach the task)
- the hostrouteif is created, if it does not exist. (work in progress)


[macvtap routing details](https://github.com/f1-outsourcing/plugins/blob/master/plugins/main/macvtap/macvtap-routing.md)

