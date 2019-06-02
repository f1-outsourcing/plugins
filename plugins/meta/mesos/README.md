# mesos delegate plugin

## Overview

We created the mesos delegate plugin to inject labels of org.apache.mesos to args.cni section of the container network. The plugin gets its configuration and injects the changes into the delegate configuration.

## Example

###### marathon task json
When we launch this task via marathon,

```
{
  "id": "/server",
  "user": "root",
  "cmd": "python -m SimpleHTTPServer 8080",
  "cpus": 0.1,
  "mem": 32,
  "disk": 0,
  "instances": 1,
  "acceptedResourceRoles": ["*"],
  "constraints": [["hostname","CLUSTER","m03.local"]],
  "backoffSeconds": 10,
  "networks": [ { "mode": "container", "name": "test-delegate","labels": {"CNI_ARGS": "IP=192.168.122.176"} } ],
  "env": {"CNI_ARGS": "IP=192.168.122.172"},
  "labels": {"CNI_ARGS": "IP=192.168.122.174"}
}
```

One can also use this configuration syntax:
"ipAddress": { "networkName": "test-delegate", "labels": {"CNI_ARGS": "IP=192.168.122.176"} },


Apache mesos injects this runtime into cni network configuration. As you can see only the entry of CNI_ARGS that is in the ipAddress section is available.
Standard cni plugins do not use this section of the configuration.

```
{
  "args": {
    "org.apache.mesos": {
      "network_info": {
        "ip_addresses": [
          {
            "protocol": "IPv4"
          }
        ],
        "labels": {
          "labels": [
            {
              "key": "CNI_ARGS",
              "value": "IP=192.168.122.176"
            }
          ]
        },
        "name": "test-delegate"
      }
    }
  }
}


```

###### cni network json
This is our cni network configuration file. The above json will be injected in the cni network confiugration on the args level. The mesos plugin will get the labels and then insert them into the delegate section before delegating to macvtap.
```
{
  "name" : "test-delegate",
  "type" : "mesos",
  "MyAwesomeFlag": false,
  "AnotherAwesomeArg": "qwerqwer",
  "delegate": {
      "type": "macvtap",
      "master": "eth1",
      "hostrouteif": "macvtap0",
      "ipam": {
        "type": "host-local",
        "subnet": "192.168.122.0/24",
        "rangeStart": "192.168.122.171",
        "rangeEnd": "192.168.122.179",
        "routes": [ { "dst": "192.168.122.22/32", "gw": "0.0.0.0" },
                { "dst": "192.168.10.153/32", "gw": "0.0.0.0" }]
      },
      "dns": { "nameservers": ["192.168.10.10"] },
      "args": {
          "test": { "rs": ["192.168.10.10"] },
          "cni": {
            "test": [
              "192.168.122.172"
            ]
          }
      }
  }
}
```

Thus the macvtap will receive this configuration

```
      "type": "macvtap",
      "master": "eth1",
      "hostrouteif": "macvtap0",
      "ipam": {
        "type": "host-local",
        "subnet": "192.168.122.0/24",
        "rangeStart": "192.168.122.171",
        "rangeEnd": "192.168.122.179",
        "routes": [ { "dst": "192.168.122.22/32", "gw": "0.0.0.0" },
                { "dst": "192.168.10.153/32", "gw": "0.0.0.0" }]
      },
      "dns": { "nameservers": ["192.168.10.10"] },
      "args": {
          "test": { "rs": ["192.168.10.10"] },
          "cni": {
            "test": [
              "192.168.122.172"
            ],
            "ips": ["192.168.122.176"]
          },
    
      }
```

## Notes

This is still under developmment. For now the CNI_ARGS='IP=x.x.x.x' is implemented. With a single ip.