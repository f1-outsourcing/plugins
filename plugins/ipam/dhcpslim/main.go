// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/client4"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ns"
	types020 "github.com/containernetworking/cni/pkg/types/020"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

type NetConf struct {
	types.NetConf
	Name       string      `json:"name"`
	CNIVersion string      `json:"cniVersion"`
	IPAM       *IPAMConfig `json:"ipam"`
	Args       struct {
		       Cni IPAMArgs `json:"cni"`
		   } `json:"args"`
}

type IPAMArgs struct {
	Ips []net.IP `json:"ips"`
}

type IPAMConfig struct {
	Name      string
	Type      string         `json:"type"`
	Routes    []*types.Route `json:"routes"`
	Addresses []Address      `json:"addresses,omitempty"`
	DhcpIf    string         `json:"dhcpif"`
	ClientID  string         `json:"clientid"`
	VendorID  string         `json:"vendorid"`
	UserID    string         `json:"userid"`
}

type IPAMEnvArgs struct {
	types.CommonArgs
	IP      types.UnmarshallableString `json:"ip,omitempty"`
	GATEWAY types.UnmarshallableString `json:"gateway,omitempty"`
}

type Address struct {
	AddressStr string `json:"address"`
	Gateway    net.IP `json:"gateway,omitempty"`
	Address    net.IPNet
	Version    string
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("dhcpslim"))
}

func cmdAdd(args *skel.CmdArgs) error {
	ipamConf, confVersion, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	result := &current.Result{}
	result.Routes = ipamConf.IPAM.Routes
	result.DNS = ipamConf.DNS

	if ipamConf.IPAM.DhcpIf == "" {
		return fmt.Errorf("No dhcp interface to use specified")
	}


	if ipamConf.Args.Cni.Ips != nil {
		cniip := net.IPNet{}
		cniip.IP =  ipamConf.Args.Cni.Ips[0]
		//get mask from args?
		cniip.Mask = net.IPv4Mask(255, 255, 255, 0)
		//get also route from args or from cni network config
		result.IPs = append(result.IPs, &current.IPConfig{Version: "4" , Address: cniip })
		return types.PrintResult(result, confVersion)
	}

	ms := []dhcpv4.Modifier{}
	ms = append(ms, dhcpv4.WithRouter())
	//ms = append(ms, dhcpv4.WithNetmask())

	if ipamConf.IPAM.VendorID != "" {
		ms = append(ms, dhcpv4.WithOption(dhcpv4.OptClassIdentifier(ipamConf.IPAM.VendorID)))
	}

	if ipamConf.IPAM.UserID != "" {
		ms = append(ms, dhcpv4.WithOption(dhcpv4.OptUserClass(ipamConf.IPAM.UserID)))
	}

	if ipamConf.IPAM.ClientID != "" {
		ms = append(ms, dhcpv4.WithOption(OptClientIdentifier(ipamConf.IPAM.ClientID)))
	} else {
		ms = append(ms, dhcpv4.WithOption(OptClientIdentifier(args.ContainerID+args.IfName)))
	}

	client := client4.NewClient()
	p, err := exchangeDHCP(client, ipamConf.IPAM.DhcpIf, ms)
	if err != nil {
		//try again
		p, err = exchangeDHCP(client, ipamConf.IPAM.DhcpIf, ms)
		if err != nil {
			//try again
			p, err = exchangeDHCP(client, ipamConf.IPAM.DhcpIf, ms)
			if err != nil {
				//try again
				p, err = exchangeDHCP(client, ipamConf.IPAM.DhcpIf, ms)
				if err != nil {
					return err
				}
			}
		}
	}

	if p.YourIPAddr.Equal(net.IPv4zero) {
		return err
	}

	dhcpip := net.IPNet{}
	dhcpip.IP =  p.YourIPAddr
	dhcpip.Mask = p.SubnetMask() 


	if len(p.Router())<=0 {
		result.IPs = append(result.IPs, &current.IPConfig{Version: "4" , Address: dhcpip} )
	} else {
		defaultNet := &net.IPNet{}
		defaultNet.IP = net.IPv4zero
		defaultNet.Mask = net.IPMask(defaultNet.IP)

		result.Routes = append(result.Routes, &types.Route{Dst: *defaultNet, GW: p.Router()[0]} )
		result.IPs = append(result.IPs, &current.IPConfig{Version: "4" , Address: dhcpip, Gateway: p.Router()[0]} )
	}

	//cant get dns to work
	dnsips := make([]string,0)
	for _, ip := range p.DNS() {
		dnsips = append(dnsips, ip.String())
	}	
	for _, ip := range result.DNS.Nameservers {
		dnsips = append(dnsips, ip)
	}
	result.DNS = types.DNS{Nameservers: dnsips }

	return types.PrintResult(result, confVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	ipamConf, _, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return nil
	}
	//ioutil.WriteFile("/tmp/dhcpslim-debug1", []byte(fmt.Sprintf("%#v\n",ipamConf)), 0644)
	client := client4.NewClient()


	// getting the ip addresses of the netns interface
	addresses := []net.Addr{} 

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return nil
	}
	defer netns.Close()
	
	err = netns.Do(func(_ ns.NetNS) error {
	
		intf, err := net.InterfaceByName(args.IfName)
		if err != nil {
			return nil
		}		
		addresses, err = intf.Addrs()

		return nil
	})

	//releasing the ip addresses via the configured dhcp if
	for _, addr := range addresses {
		switch ip := addr.(type) {
			case *net.IPNet:
				_, err := client.Release(ipamConf.IPAM.DhcpIf, dhcpv4.WithClientIP(ip.IP))
				if err != nil {
					return nil
				}		
		}
	}

	return nil
}

func cmdCheck(args *skel.CmdArgs) error {

	return nil
}




func exchangeDHCP(c *client4.Client, dev string, modifiers []dhcpv4.Modifier) (*dhcpv4.DHCPv4, error) {
        ps, err := c.Exchange(dev, modifiers...)
        if err != nil {
                //could not exchange DHCP with %s
                return nil, err
        }
        if len(ps) < 1 {
                //got empty DHCP message
                return nil, err
        }
        var ack *dhcpv4.DHCPv4
        for _, p := range ps {
                if p.MessageType() == dhcpv4.MessageTypeAck {
                        ack = p
                }
        }
        if ack == nil {
                //did not get DHCPACK
                return nil, err
        }
        return ack, nil
}

func OptClientIdentifier(name string) dhcpv4.Option {
	return dhcpv4.Option{Code: dhcpv4.OptionClientIdentifier, Value: dhcpv4.String(name)}
}

func canonicalizeIP(ip *net.IP) error {
	if ip.To4() != nil {
		*ip = ip.To4()
		return nil
	} else if ip.To16() != nil {
		*ip = ip.To16()
		return nil
	}
	return fmt.Errorf("IP %s not v4 nor v6", *ip)
}

func LoadIPAMConfig(bytes []byte, envArgs string) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, "", err
	}

	if n.IPAM == nil {
		return nil, "", fmt.Errorf("IPAM config missing 'ipam' key")
	}

	// Validate all ranges
	numV4 := 0
	numV6 := 0

	for i := range n.IPAM.Addresses {
		ip, addr, err := net.ParseCIDR(n.IPAM.Addresses[i].AddressStr)
		if err != nil {
			return nil, "", fmt.Errorf("invalid CIDR %s: %s", n.IPAM.Addresses[i].AddressStr, err)
		}
		n.IPAM.Addresses[i].Address = *addr
		n.IPAM.Addresses[i].Address.IP = ip

		if err := canonicalizeIP(&n.IPAM.Addresses[i].Address.IP); err != nil {
			return nil, "", fmt.Errorf("invalid address %d: %s", i, err)
		}

		if n.IPAM.Addresses[i].Address.IP.To4() != nil {
			n.IPAM.Addresses[i].Version = "4"
			numV4++
		} else {
			n.IPAM.Addresses[i].Version = "6"
			numV6++
		}
	}

	if envArgs != "" {
		e := IPAMEnvArgs{}
		err := types.LoadArgs(envArgs, &e)
		if err != nil {
			return nil, "", err
		}

		if e.IP != "" {
			for _, item := range strings.Split(string(e.IP), ",") {
				ipstr := strings.TrimSpace(item)

				ip, subnet, err := net.ParseCIDR(ipstr)
				if err != nil {
					return nil, "", fmt.Errorf("invalid CIDR %s: %s", ipstr, err)
				}

				addr := Address{Address: net.IPNet{IP: ip, Mask: subnet.Mask}}
				if addr.Address.IP.To4() != nil {
					addr.Version = "4"
					numV4++
				} else {
					addr.Version = "6"
					numV6++
				}
				n.IPAM.Addresses = append(n.IPAM.Addresses, addr)
			}
		}

		if e.GATEWAY != "" {
			for _, item := range strings.Split(string(e.GATEWAY), ",") {
				gwip := net.ParseIP(strings.TrimSpace(item))
				if gwip == nil {
					return nil, "", fmt.Errorf("invalid gateway address: %s", item)
				}

				for i := range n.IPAM.Addresses {
					if n.IPAM.Addresses[i].Address.Contains(gwip) {
						n.IPAM.Addresses[i].Gateway = gwip
					}
				}
			}
		}
	}

	// CNI spec 0.2.0 and below supported only one v4 and v6 address
	if numV4 > 1 || numV6 > 1 {
		for _, v := range types020.SupportedVersions {
			if n.CNIVersion == v {
				return nil, "", fmt.Errorf("CNI version %v does not support more than 1 address per family", n.CNIVersion)
			}
		}
	}

	// Copy net name into IPAM so not to drag Net struct around
	n.IPAM.Name = n.Name

	return n, n.CNIVersion, nil
}
