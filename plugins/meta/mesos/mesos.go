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

// This is a "meta-plugin". It reads in its own netconf, combines it with
// the data from flannel generated subnet file and then invokes a plugin
// like bridge or ipvlan to do the real work.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"

	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

const (
	defaultSubnetFile = "/tmp/subnet.env"
	defaultDataDir    = "/tmp"
)

type NetConf struct {
	types.NetConf
	Args  map[string]interface{} `json:"args"`
	SubnetFile string                 `json:"subnetFile"`
	DataDir    string                 `json:"dataDir"`
	Delegate   map[string]interface{} `json:"delegate"`
}

type subnetEnv struct {
	nw     *net.IPNet
	sn     *net.IPNet
	mtu    *uint
	ipmasq *bool
}

func (se *subnetEnv) missing() string {
	m := []string{}

	if se.nw == nil {
		m = append(m, "FLANNEL_NETWORK")
	}
	if se.sn == nil {
		m = append(m, "FLANNEL_SUBNET")
	}
	if se.mtu == nil {
		m = append(m, "FLANNEL_MTU")
	}
	if se.ipmasq == nil {
		m = append(m, "FLANNEL_IPMASQ")
	}
	return strings.Join(m, ", ")
}

func loadFlannelNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{
		SubnetFile: defaultSubnetFile,
		DataDir:    defaultDataDir,
	}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, nil
}

func loadFlannelSubnetEnv(fn string) (*subnetEnv, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	se := &subnetEnv{}

	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.SplitN(s.Text(), "=", 2)
		switch parts[0] {
		case "FLANNEL_NETWORK":
			_, se.nw, err = net.ParseCIDR(parts[1])
			if err != nil {
				return nil, err
			}

		case "FLANNEL_SUBNET":
			_, se.sn, err = net.ParseCIDR(parts[1])
			if err != nil {
				return nil, err
			}

		case "FLANNEL_MTU":
			mtu, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil {
				return nil, err
			}
			se.mtu = new(uint)
			*se.mtu = uint(mtu)

		case "FLANNEL_IPMASQ":
			ipmasq := parts[1] == "true"
			se.ipmasq = &ipmasq
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	if m := se.missing(); m != "" {
		return nil, fmt.Errorf("%v is missing %v", fn, m)
	}

	return se, nil
}

func saveScratchNetConf(containerID, dataDir string, netconf []byte) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dataDir, containerID)
	return ioutil.WriteFile(path, netconf, 0600)
}

func consumeScratchNetConf(containerID, dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, containerID)
	// Ignore errors when removing - Per spec safe to continue during DEL
	defer os.Remove(path)

	return ioutil.ReadFile(path)
}

func delegateAdd(cid, dataDir string, netconf map[string]interface{}) error {
	netconfBytes, err := json.Marshal(netconf)
	if err != nil {
		return fmt.Errorf("error serializing delegate netconf: %v", err)
	}

	// save the rendered netconf for cmdDel
	if err = saveScratchNetConf(cid, dataDir, netconfBytes); err != nil {
		return err
	}

	result, err := invoke.DelegateAdd(context.TODO(), netconf["type"].(string), netconfBytes, nil)
	if err != nil {
		return err
	}

	return result.Print()
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
	n, err := loadFlannelNetConf(args.StdinData)
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
			return fmt.Errorf("'delegate' dictionary must not have 'name' field, it'll be set by flannel")
		}
	}
	file, err := os.Create("/tmp/args.log")
	if err != nil {
		return fmt.Errorf("failed to open file %v", err)
	}
	a,_:=json.Marshal(n)
	fmt.Fprintf(file, "%c\n", a)
	return doCmdAdd(args, n)
}

func cmdDel(args *skel.CmdArgs) error {
	nc, err := loadFlannelNetConf(args.StdinData)
	file, err := os.Create("/tmp/cni2.log")
	if err != nil {
		return fmt.Errorf("failed to open file %v", err)
	}

	fmt.Fprintf(file, "%c\n", args.StdinData)
	if err != nil {
		return err
	}

	return doCmdDel(args, nc)
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("flannel"))
}

func cmdCheck(args *skel.CmdArgs) error {
	// TODO: implement
	return nil
}
func getValueJson (s map[string]interface{},k string) (error,map[string]interface{}){
	var result   map[string]interface{}
	b,_:=json.Marshal(s[k])
	err := json.Unmarshal(b, &result)
	if err != nil {
		return fmt.Errorf("failed unmarshal Json %v", err),nil
	}

	return nil,result
}
func doCmdAdd(args *skel.CmdArgs, n *NetConf) error {
	//f1 edit
	type Cni struct {
		Ips []string `json:"ips"`
	}
	type Arg struct {
		Cni Cni `json:"cni"`
	}
/*	type Cni struct {
		Ips []string
	}

	fmt.Println("hi")
	var ips []string
	ips = append(ips,"192.168.122.178","192.168.122.178","192.168.122.178","192.168.122.178")

	ax :=  &Cni{Ips:c,
	}
	fmt.Println(ax)
	b,_:=json.Marshal(ax)
	fmt.Println(string(b))*/


	jsonStr := `{"args": { "cni": { "ips": ["192.168.122.178"] } } }`
	cniMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(jsonStr), &cniMap)
	if err != nil {
		return err
	}
	file, err := os.Create("/tmp/cni4.log")
	if err != nil {
		return fmt.Errorf("failed to open file %v", err)
	}

	fmt.Fprintf(file, "%c\n",cniMap)
	n.Delegate["args"]=cniMap["args"]

	if n.CNIVersion != "" {
		n.Delegate["cniVersion"] = n.CNIVersion
	}

	n.Delegate["name"] = n.Name
	file, err = os.Create("/tmp/cni3.log")
	if err != nil {
		return fmt.Errorf("failed to open file %v", err)
	}

	fmt.Fprintf(file, "%c\n", n.Delegate)
	file, err = os.Create("/tmp/cni5.log")
	if err != nil {
		return fmt.Errorf("failed to open file %v", err)
	}

	err,r :=getValueJson(n.Args,"org.apache.mesos")
	err,r =getValueJson(r,"network_info")
	err,r =getValueJson(r,"labels")


	var a   map[string]interface{}
	b,_:=json.Marshal(n.Args["org.apache.mesos"])
	err = json.Unmarshal(b, &a)


	var labless   []map[string]string
	z,_:=json.Marshal(r["labels"])
	err = json.Unmarshal(z, &labless)
	var ips []string

	for i := 0;i< len(labless) ; i++ {
		ips = append(ips,labless[i]["value"])
	}
	ax :=  Arg{ Cni{Ips:ips,}}
	bcx,_:=json.Marshal(ax)
	cniMap = make(map[string]interface{})
	err = json.Unmarshal([]byte(bcx), &cniMap)
	if err != nil {
		return err
	}
	fmt.Fprintf(file, "%c\n", len(labless),"\n\n", cniMap)
	n.Delegate["args"] = cniMap
	return  delegateAdd(args.ContainerID, n.DataDir, n.Delegate)
}

func doCmdDel(args *skel.CmdArgs, n *NetConf) error {
	netconfBytes, err := consumeScratchNetConf(args.ContainerID, n.DataDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Per spec should ignore error if resources are missing / already removed
			return nil
		}
		return err
	}

	nc := &types.NetConf{}
	if err = json.Unmarshal(netconfBytes, nc); err != nil {
		return fmt.Errorf("failed to parse netconf: %v", err)
	}

	return invoke.DelegateDel(context.TODO(), nc.Type, netconfBytes, nil)
}
