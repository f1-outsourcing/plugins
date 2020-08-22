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

// This is a "meta-plugin". It reads in its own netconf, and then invokes 
// a plugin like bridge or ipvlan to do the real work.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"os"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	//"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"

	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

type NetConf struct {
	types.NetConf

	Delegate   map[string]interface{} `json:"delegate"`
}

type CniArgs struct {
	Args struct {
		Cni IPAMArgs `json:"cni"`
	} `json:"args"`
}

type IPAMArgs struct {
	Ips []net.IP `json:"ips"`
	Subnet *net.IPNet `json:"subnet"`
}

type MesosArgs struct {
	Args struct {
		OrgApacheMesos struct {
			NetworkInfo struct {
				IpAddrs []struct {
					Prot string `json:"protocol"`
					
				} `json:"ip_addresses"`
				Labels struct {
					Labels []struct {
						Key string `json:"key"`
						Value string `json:"value"`
					}  `json:"labels"`
				}  `json:"labels"`
				Name string `json:"name"`
			} `json:"network_info"`
		} `json:"org.apache.mesos"`
	} `json:"args"`
}

func loadMesosNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, nil
}

func loadMesosArgsConf(bytes []byte) (*MesosArgs, error) {
	m := &MesosArgs{}
	if err := json.Unmarshal(bytes, m); err != nil {
		return nil, fmt.Errorf("failed to load args: %v", err)
	}

	return m,nil
}

func delegateAdd(cid, dataDir string, netconf map[string]interface{}) error {
	netconfBytes, err := json.Marshal(netconf)
	if err != nil {
		return fmt.Errorf("error serializing delegate netconf: %v", err)
	}
	
	result, err := invoke.DelegateAdd(context.TODO(), netconf["type"].(string), netconfBytes, nil)
	if err != nil {
		return err
	}

	return result.Print()
	//return types.PrintResult(netconf.PrevResult, netconf.CNIVersion)
}

func delegateDel(cid, dataDir string, netconf map[string]interface{}) error {
	netconfBytes, err := json.Marshal(netconf)
	if err != nil {
		return fmt.Errorf("error serializing delegate netconf: %v", err)
	}

	err = invoke.DelegateDel(context.TODO(), netconf["type"].(string), netconfBytes, nil)
	if err != nil {
		return err
	}

	return nil
}

func hasKey(m map[string]interface{}, k string) bool {
	_, ok := m[k]
	return ok
}

func isString(i interface{}) bool {
	_, ok := i.(string)
	return ok
}

func cmdAdd(args *skel.CmdArgs) error {
	n, err := loadMesosNetConf(args.StdinData)
	if err != nil {
		return err
	}

        cniargs := CniArgs{}

	//getting the mesos args from stdin
	m, err := loadMesosArgsConf(args.StdinData)
	if err != nil {
		return err
	}

	bla, err := json.Marshal(m)
	
	if n.Delegate == nil {
		n.Delegate = make(map[string]interface{})
	} else {
		if hasKey(n.Delegate, "type") && !isString(n.Delegate["type"]) {
			return fmt.Errorf("'delegate' dictionary, if present, must have (string) 'type' field")
		}
		if hasKey(n.Delegate, "name") {
			return fmt.Errorf("'delegate' dictionary must not have 'name' field")
		}
		if hasKey(n.Delegate, "args") {
			//f1 edit fix marshall unmarshall 
			//read the already existing args cni section
			bla, err = json.Marshal(n.Delegate)
			if err != nil { return fmt.Errorf("error serializing delegate") }
        		if err := json.Unmarshal(bla, &cniargs); err != nil {
                		return fmt.Errorf("'delegate' failed to load args: %v", err)
        		}
		}
	}

	//read the values of m and put them in cniargs
	//or ipam
	items := m.Args.OrgApacheMesos.NetworkInfo.Labels.Labels
	for _, item := range items {

		// modify args
		if item.Key == "CNI_ARGS" {
			s := strings.Split(item.Value,";")
			for _, element := range s {
				v := strings.Split(element,"=")
				if v[0] == "IP" {
					ip,net,_ := net.ParseCIDR(v[1])
					
					cniargs.Args.Cni.Ips=append(cniargs.Args.Cni.Ips, ip)
					cniargs.Args.Cni.Subnet=net
				}
			}
		}

		//modify ipam args
		if item.Key == "vendorid" {
			if hasKey(n.Delegate, "ipam") {
				if hasKey(n.Delegate["ipam"].(map[string]interface{}), "vendorid") {
					n.Delegate["ipam"].(map[string]interface{})["vendorid"] = item.Value
				} else {
					//create the key
					n.Delegate["ipam"].(map[string]interface{})["vendorid"] = make(map[string]interface{})
					n.Delegate["ipam"].(map[string]interface{})["vendorid"] = item.Value
				}
			}	
		}

		if item.Key == "userid" {
			if hasKey(n.Delegate, "ipam") {
				if hasKey(n.Delegate["ipam"].(map[string]interface{}), "userid") {
					n.Delegate["ipam"].(map[string]interface{})["userid"] = item.Value
				} else {
					//create the key
					n.Delegate["ipam"].(map[string]interface{})["userid"] = make(map[string]interface{})
					n.Delegate["ipam"].(map[string]interface{})["userid"] = item.Value
				}
			}	
		}

		if item.Key == "clientid" {
			if hasKey(n.Delegate, "ipam") {
				if hasKey(n.Delegate["ipam"].(map[string]interface{}), "clientid") {
					n.Delegate["ipam"].(map[string]interface{})["clientid"] = item.Value
				} else {
					//create the key
					n.Delegate["ipam"].(map[string]interface{})["clientid"] = make(map[string]interface{})
					n.Delegate["ipam"].(map[string]interface{})["clientid"] = item.Value
				}
			}	
		}

		//modify the netns
		netns, err := ns.GetNS(args.Netns)
		if err != nil {
			return fmt.Errorf("failed to open netns %q: %v", netns, err)
		}
		defer netns.Close()

		err = netns.Do(func(_ ns.NetNS) error {

			if item.Key == "env" {
				s := strings.Split(item.Value,"=")
				os.Setenv(s[0], s[1])
			}

			if item.Key == "hostname" {
				/*
				cmd := exec.Command("hostname", item.Value)
				err := cmd.Run()
				if err != nil {
					return fmt.Errorf("Cannot set hostname: %v", err)
				}
				if err := syscall.Sethostname([]byte(item.Value)); err != nil {
					return fmt.Errorf("Sethostname: %v", err)
				}
				*/
			}

		return nil
		})

	}

	ipamargs := IPAMArgs{}
	ipamargs = cniargs.Args.Cni

	if hasKey(n.Delegate, "args") {
		n.Delegate["args"].(map[string]interface{})["cni"]=ipamargs
	} else {
		n.Delegate["args"]=make(map[string]interface{})
		n.Delegate["args"].(map[string]interface{})["cni"]=ipamargs
	}

	if hasKey(n.Delegate, "prevResult") {
		n.Delegate["prevResult"].(map[string]interface{})["prevResult"]=n.RawPrevResult
	} else {
		n.Delegate["prevResult"]=make(map[string]interface{})
		n.Delegate["prevResult"].(map[string]interface{})["prevResult"]=n.RawPrevResult
	}

        if n.CNIVersion != "" {
                n.Delegate["cniVersion"] = n.CNIVersion
        }
	
        n.Delegate["name"] = n.Name

        return delegateAdd(args.ContainerID, "", n.Delegate)
}

func cmdDel(args *skel.CmdArgs) error {
	n, err := loadMesosNetConf(args.StdinData)
	if err != nil {
		return err
	}


	//we still need to have this configuration parsed?
	jsonStr := `{"args": { "cni": { "ips": ["192.168.122.176"] } } }`
	cniMap := make(map[string]interface{})
	err = json.Unmarshal([]byte(jsonStr), &cniMap)
	if err != nil {
		return err
	}
	n.Delegate["args"] = cniMap["args"]
        n.Delegate["name"] = n.Name


     return delegateDel(args.ContainerID, "", n.Delegate)
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("mesos"))
}

func cmdCheck(args *skel.CmdArgs) error {

        n, err := loadMesosNetConf(args.StdinData)
        if err != nil {
                return err
        }


        // Parse previous result.
        if n.NetConf.RawPrevResult == nil {
                return fmt.Errorf("Required prevResult missing")
        }

        if err := version.ParsePrevResult(&n.NetConf); err != nil {
                return err
        }




	return nil
}
