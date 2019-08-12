// Copyright 2016 CNI authors
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

// This is a "meta-plugin". It reads in its own netconf, it does not create
// any network interface but just changes the network sysctl.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"

	"io/ioutil"
	"os"
)

const (
	defaultDataDir = "/etc/mesos"
)

// FirewallNetConf represents the firewall configuration.
type FirewallNetConf struct {
	types.NetConf
	
	DataDir  string   `json:"dataDir"`
	FwFiles  []string `json:"fwFiles"`

	Ipsets   []Ipset  `json:"ipsets"`
	Policies []Policy `json:"policies"`
	Rules    []Rule	  `json:"rules"`
}

type Ipset struct {
        Set        string `json:"set"`
        HashType   string `json:"hashtype"`
        HashFamily string `json:"hashfamily"`
        HashSize   int `json:"hashsize"`
        Netmask    int `json:"netmask"`
        MaxElem    int `json:"maxElem"`
        Timeout    int `json:"timeout"`
}

type Policy struct {
	Policy string `json:"policy"`
	Chain  string `json:"chain"`
}

type Rule struct {
	Type  string `json:"type"`
	Chain string `json:"chain"`
	Rule  string `json:"rule"`
}

func logtofile(data []byte) {
	ioutil.WriteFile("/tmp/firewallnetns-debug", data, 0644)
}

func parseConf(data []byte) (*FirewallNetConf, *current.Result, error) {
	var result *current.Result
	var err error

	conf := FirewallNetConf{}

	if err = json.Unmarshal(data, &conf); err != nil {
		return nil, nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	// Parse previous result.
	if conf.RawPrevResult == nil {
		return &conf, result, nil 
	}

	// Parse previous result.
	if err = version.ParsePrevResult(&conf.NetConf); err != nil {
		return nil, nil, fmt.Errorf("could not parse prevResult: %v", err)
	}

	result, err = current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return nil, nil, fmt.Errorf("could not convert result to current version: %v", err)
	}

	return &conf, result, nil
}


func cmdAdd(args *skel.CmdArgs) error {
	conf, result, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}
	
	logtofile(args.StdinData)
	logtofile([]byte(fmt.Sprintf("%#v\n",os.Environ())))

	//#########################

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	err = netns.Do(func(_ ns.NetNS) error {

		if conf.DataDir == "" { conf.DataDir = defaultDataDir }

		// first process the files in the config		
		err := processFiles(conf)
		if err != nil {
			return fmt.Errorf("Error processing files %v", err)
		}
	
		// now process the lines in the config	
		err = applyFirewallFile(conf)
		if err != nil {
			return fmt.Errorf("Error processing rules %v", err)
		}

	return nil
	})
	if err != nil {
		return err
	}

	//#########################


	if result == nil {
		result = &current.Result{}
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {

	// Tolerate errors if the container namespace has been torn down already
	netNS, err := ns.GetNS(args.Netns)
	if err == nil {
		defer netNS.Close()

		netNS.Do(func(_ ns.NetNS) error {

		flushFirewall()

		return nil
		})
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.PluginSupports("0.3.1"), bv.BuildString("firewallnetns"))
}

func cmdCheck(args *skel.CmdArgs) error {

	return nil
}
