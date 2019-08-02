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
	"fmt"
	"net"
	"github.com/vishvananda/netlink"

)

func addHostRoute(ifName string, contip net.IP) error {

	hostlink, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	//bring up interface
	if err := netlink.LinkSetUp(hostlink); err != nil {
		return err
       	}

       	hostdst := &net.IPNet{
		IP:   contip.To4(),
		Mask: net.CIDRMask(32, 32),
       	}

	hostroute := netlink.Route{LinkIndex: hostlink.Attrs().Index, Dst: hostdst}

	if err := netlink.RouteAdd(&hostroute); err != nil {
		return fmt.Errorf("Failed to add host route %q: %v", ifName, err)
       	}

	return nil
}

func delHostRoute(ifName string, contip net.IP) error {
		
	hostlink, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

       	hostdst := &net.IPNet{
		IP:   contip.To4(),
		Mask: net.CIDRMask(32, 32),
       	}

	hostroute := netlink.Route{LinkIndex: hostlink.Attrs().Index, Dst: hostdst}

	if err := netlink.RouteDel(&hostroute); err != nil {
		return err
       	}

	return nil	
}

func addContRoute(ifName string, hostip net.IP) error {

	contlink, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	//bring up interface
	if err := netlink.LinkSetUp(contlink); err != nil {
		return err
       	}

       	hostdst := &net.IPNet{
		IP:   hostip.To4(),
		Mask: net.CIDRMask(32, 32),
       	}

	controute := netlink.Route{LinkIndex: contlink.Attrs().Index, Dst: hostdst}

	//we need to use table 1
	//ip route show table 1
	controute.Table = contlink.Attrs().Index

	if err := netlink.RouteAdd(&controute); err != nil {
		return fmt.Errorf("Failed to add container route %s %q: %v", ifName, hostip,err)
       	}

	return nil
}

func addContRule(ifName string, hostip net.IP) error {

	contlink, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	nsrule := netlink.NewRule()
	
       	contfrom := &net.IPNet{
		IP:   hostip.To4(),
		Mask: net.CIDRMask(32, 32),
       	}
	nsrule.Src = contfrom
	nsrule.Table = contlink.Attrs().Index

	if err := netlink.RuleAdd(nsrule); err != nil {
		return fmt.Errorf("Failed to add rule nsrule:%v err:%v",nsrule,err)
	}

	return nil
}

func delContRule(ifName string, hostip net.IP) error {

	contlink, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	nsrule := netlink.NewRule()
	
       	contfrom := &net.IPNet{
		IP:   hostip.To4(),
		Mask: net.CIDRMask(32, 32),
       	}
	nsrule.Src = contfrom
	nsrule.Table = contlink.Attrs().Index

	if err := netlink.RuleDel(nsrule); err != nil {
		return fmt.Errorf("Failed to delete rule nsrule:%v err:%v",nsrule,err)
	}

	return nil
}

func delContRoute(ifName string, hostip net.IP) error {

	contlink, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

       	hostdst := &net.IPNet{
		IP:   hostip.To4(),
		Mask: net.CIDRMask(32, 32),
       	}

	controute := netlink.Route{LinkIndex: contlink.Attrs().Index, Dst: hostdst}

	//we need to use table 1
	controute.Table = contlink.Attrs().Index

	if err := netlink.RouteDel(&controute); err != nil {
		return fmt.Errorf("Failed to delete container route %q: %v", ifName, err)
       	}

	return nil
}


/*
func main() {
        ipaddress :=  net.IP{13,13,13,13}	
	addContRoute("tun1cnivtap", ipaddress )
}
*/

