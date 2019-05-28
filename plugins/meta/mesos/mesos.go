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

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"

	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

type NetConf struct {
	types.NetConf

	DataDir    string                 `json:"dataDir"`
	Delegate   map[string]interface{} `json:"delegate"`
}

type subnetEnv struct {
	nw     *net.IPNet
	sn     *net.IPNet
	mtu    *uint
	ipmasq *bool
}

func loadMesosNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, nil
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

	if n.Delegate == nil {
		n.Delegate = make(map[string]interface{})
	} else {
		if hasKey(n.Delegate, "type") && !isString(n.Delegate["type"]) {
			return fmt.Errorf("'delegate' dictionary, if present, must have (string) 'type' field")
		}
		if hasKey(n.Delegate, "name") {
			return fmt.Errorf("'delegate' dictionary must not have 'name' field")
		}
	}

	return doCmdAdd(args, n)
}

func cmdDel(args *skel.CmdArgs) error {
	nc, err := loadMesosNetConf(args.StdinData)
	if err != nil {
		return err
	}

	return doCmdDel(args, nc)
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("mesos"))
}

func cmdCheck(args *skel.CmdArgs) error {
	// TODO: implement
	return nil
}

func doCmdAdd(args *skel.CmdArgs, n *NetConf) error {

	//f1 edit
	jsonStr := `{"args": { "cni": { "ips": ["192.168.122.176"] } } }`
	cniMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(jsonStr), &cniMap)
	if err != nil {
		return err
	}
	n.Delegate["args"]=cniMap["args"]

        if n.CNIVersion != "" {
                n.Delegate["cniVersion"] = n.CNIVersion
        }
	
        n.Delegate["name"] = n.Name

        return delegateAdd(args.ContainerID, n.DataDir, n.Delegate)
}

func doCmdDel(args *skel.CmdArgs, n *NetConf) error {

	//f1 edit
	jsonStr := `{"args": { "cni": { "ips": ["192.168.122.176"] } } }`
	cniMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(jsonStr), &cniMap)
	if err != nil {
		return err
	}
	n.Delegate["args"]=cniMap["args"]
        n.Delegate["name"] = n.Name


     //return invoke.DelegateDel(context.TODO(), nc.Type, netconfBytes, nil)
     return delegateDel(args.ContainerID, n.DataDir, n.Delegate)
}

