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
	"strings"
	"os"
	"io/ioutil"

	"github.com/f1-outsourcing/go-iptables/iptables"
	"github.com/f1-outsourcing/go-ipset/ipset"
)

func loadFirewallFile(fwc *FirewallNetConf, fn string) error {
	f, err := os.Open(fn)
	if err != nil { return fmt.Errorf("Error opening file %v",err) }
	defer f.Close()

	fc,_ := ioutil.ReadAll(f)

	err = json.Unmarshal(fc,fwc)
	
	return err
}


func flushFirewall() {

	ipt,_ := iptables.New()

		
	//maybe drop ipsets?

	_ = ipt.ChangePolicy("filter", "INPUT", "ACCEPT")
	_ = ipt.ChangePolicy("filter", "OUTPUT", "ACCEPT")
	_ = ipt.ChangePolicy("filter", "FORWARD", "ACCEPT")

	_ = ipt.ClearChain("filter", "INPUT")
	_ = ipt.ClearChain("filter", "OUTPUT")
	_ = ipt.ClearChain("filter", "FORWARD")


}

func applyFirewallFile(fwc *FirewallNetConf) error {

	// process ipset lists
	contipsets := fwc.Ipsets

	for _, item := range contipsets {
		_, err  := ipset.New(item.Set, item.HashType, &ipset.Params{HashFamily: item.HashFamily, HashSize: item.HashSize, Netmask: item.Netmask, MaxElem: item.MaxElem, Timeout: item.Timeout})
		if err != nil {
			return fmt.Errorf("Ipset create failed: %v",err)
		}
	}
	
	// process policies
	ipt, err := iptables.New()

	contpolicies := fwc.Policies
	for _, item := range contpolicies {
		err = ipt.ChangePolicy("filter", item.Chain, item.Policy)
		if err != nil {
			return fmt.Errorf("ChangePolicy failed: %v", err)
			return err
			}
	}


	// process rules
	contrules := fwc.Rules

	for _, item := range contrules {
		if item.Type == "A" {
			err = ipt.Append("filter", item.Chain, strings.Fields(item.Rule)... )
			if err != nil {
				return fmt.Errorf("Append failed: %v", err)
			}
		}
	}


	return nil
}

func processFiles(conf *FirewallNetConf) error {

	fw := FirewallNetConf{}
	
	for _, file := range conf.FwFiles {
		
		filepath := conf.DataDir + "/" + file + ".fw"
		err := loadFirewallFile(&fw, filepath)
		if err != nil {
			return fmt.Errorf("error loading files %v", err)
		}

		err = applyFirewallFile(&fw)
		if err != nil {
			return fmt.Errorf("error applying file %v", err)
		}
	}

	return nil
}


