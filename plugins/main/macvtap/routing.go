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
	"golang.org/x/sys/unix"
	//"github.com/containernetworking/plugins/pkg/ns"

)


func FixContHostNet (hostip net.IP) error {

	// not working??? fix!
	//hostip[3] = 2
	testip := net.IP{192, 168, 10, 2}

	routes,_ := netlink.RouteGet(testip)

	for _, route := range routes {

		// add the container route
		contlink,_ := netlink.LinkByIndex(route.LinkIndex)
		err := addContRoute(contlink, hostip)
		if err != nil {
			return fmt.Errorf("Failed to add container route %s %s: %v", contlink, hostip, err)
		}
		// add the container rule
		err = addContRules(contlink, hostip)
		if err != nil {
			return fmt.Errorf("Failed to add container route %s %s: %v", contlink, hostip, err)
		}
		
		// remove the network route from table main
		mvroute := netlink.Route{}
		mvroute.LinkIndex =  route.LinkIndex
		mvroute.Src = route.Src
		mvroute.Dst = route.Dst 
		mvroute.Scope = netlink.SCOPE_LINK
		testip[3] = 0
		mvroute.Dst= &net.IPNet{
			IP:   testip.To4(),
			Mask: net.CIDRMask(24, 32),
      			}

		err = netlink.RouteDel(&mvroute)
		if err != nil {
			return err
		}

		// put the network route back in table default
		mvroute.Table = unix.RT_TABLE_DEFAULT
		err = netlink.RouteAdd(&mvroute)
		if err != nil {
			return err
		}
	}

	return nil
} 

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
		//return fmt.Errorf("Failed to add host route %q: %v", ifName, err)
		return nil
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

func addContRoute(contlink netlink.Link, hostip net.IP) error {


	//bring up interface
	if err := netlink.LinkSetUp(contlink); err != nil {
		return err
       	}

       	hostdst := &net.IPNet{
		IP:   hostip.To4(),
		Mask: net.CIDRMask(32, 32),
       	}

	controute := netlink.Route{LinkIndex: contlink.Attrs().Index, Dst: hostdst}

	//we need to use table 
	//ip route show table 
	controute.Table = contlink.Attrs().Index

	if err := netlink.RouteAdd(&controute); err != nil {
		return fmt.Errorf("Failed to add container route %s %q: %v", contlink, hostip,err)
       	}

	//we need to such a route in the table default
        //but it needs to be having the gateway if, if there is a gateway
	controute.Table = unix.RT_TABLE_DEFAULT

	if HasGwRoute(contlink) {
		if err := netlink.RouteReplace(&controute); err != nil {
			return fmt.Errorf("Failed to add container route %s %q: %v", contlink, hostip,err)
      	 	}
	} else {
		// we do not want to change a route made for the gateway interface
		netlink.RouteAdd(&controute)

	}

	return nil
}

func addContRules(contlink netlink.Link, hostip net.IP) error {

	contips,_ := netlink.AddrList(contlink, unix.AF_INET)
	// brrr
	contip := contips[0].IPNet
	

	// get rules for priority and existence of main
	rules,_ := netlink.RuleList(unix.AF_INET) 

	foundmain := false
	lastprio := 100 
	for _, nsrule := range rules {
		if nsrule.Priority == 5 { foundmain = true }
		if nsrule.Priority > 5 { 
			lastprio = nsrule.Priority
			break
		}
	}

	// add ip rule from
	// ip rule add from x.x.x.x(ifidx) table x
	nsrule := netlink.NewRule()
	
	nsrule.Priority = lastprio - 1 
	nsrule.Src = contip
	nsrule.Src.Mask = net.CIDRMask(32, 32)

	nsrule.Table = contlink.Attrs().Index

	if err := netlink.RuleAdd(nsrule); err != nil {
		return fmt.Errorf("Failed to add rule nsrule:%v err:%v",nsrule,err)
	}

	// add ip rule to 
	// ip rule add from all to 192.168.x.x table x
	/*
       	contfrom := &net.IPNet{
		IP:   hostip.To4(),
		Mask: net.CIDRMask(32, 32),
       	}

	nsrule = netlink.NewRule()
	nsrule.Priority = lastprio - 2 
	nsrule.Dst = contfrom
	nsrule.Table = contlink.Attrs().Index

	if err := netlink.RuleAdd(nsrule); err != nil {
		return fmt.Errorf("Failed to add rule nsrule:%v err:%v",nsrule,err)
	}
	*/

	// add rule to main with reserved 254
	// ip rule add prio 5 from all table main
	if foundmain != true { 	
		nsrule = netlink.NewRule()
		nsrule.Priority = 5 
		nsrule.Table = unix.RT_TABLE_MAIN

		// skip for now
		//rules := netlink.RuleListFiltered(unix.AF_INET,nsrule,RT_FILTER_PRIORITY) 
		if err := netlink.RuleAdd(nsrule); err != nil {
			return fmt.Errorf("Failed to add rule nsrule:%v err:%v",nsrule,err)
		}
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

func MultipleLinks() ([]netlink.Link, error) {
	rval := []netlink.Link{};

	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	for _,link := range links {
		
		if link.Attrs().EncapType == "ether" && link.Attrs().Flags&net.FlagUp != 0 {
			rval = append(rval, link)
		}
	}

	return rval, nil
}

func GetGwRoutes(links []netlink.Link) ([]netlink.Route, error) {
	rval := []netlink.Route{}

	for _, link := range links {
		lnkroutes, _ := netlink.RouteList(link, netlink.FAMILY_V4)
		for _, lnkroute := range lnkroutes {
			if lnkroute.Gw != nil {
				rval = append(rval, lnkroute)
			}

		}

	}
	
	return rval, nil
}

func HasGwRoute(link netlink.Link) (bool) {
	rval := false
	lnkroutes, _ := netlink.RouteList(link, netlink.FAMILY_V4)
	for _, lnkroute := range lnkroutes {
		if lnkroute.Gw != nil {
			rval = true
		}
	}
	return rval
}


func ReplaceGwRoutes(routes []netlink.Route, hostip net.IP) error {

	for _, route := range routes {

		rtroute := route

		//adding routing table routes 
		//rtroute.Table = rtroute.LinkIndex
		rtroute.Table = unix.RT_TABLE_DEFAULT
		err := netlink.RouteAdd(&rtroute)
		if err != nil {
			return err
		}

		/*
		intf, err := net.InterfaceByIndex(rtroute.LinkIndex)
		if err != nil {
			return err
		}

		addresses, err := intf.Addrs()
		for _, addr := range addresses {
			switch ip := addr.(type) {
				case *net.IPNet:
					if ip.IP.DefaultMask() != nil { 

						//adding routing table rules
						addContRules(rtroute.LinkIndex, ip.IP)
					}
			}
		}
		*/

		//deleting the current default gw
		err = netlink.RouteDel(&route)
		if err != nil {
			return err
		}

	}


	return nil
}

/*
func main() {

	fmt.Println("testtest ")

	//test on networkns
	netns, err := ns.GetNS("/run/netns/testing")
	if err != nil {
		fmt.Printf("failed to open netns %q: %v", "testing", err)
	}
	defer netns.Close()

	err = netns.Do(func(_ ns.NetNS) error {
	
		links, err := MultipleLinks() 
		if err != nil {
			fmt.Printf("Failed to open links")
		}

		gwroutes, err := GetGwRoutes(links)

		if len(links)>1 && len(gwroutes)>0 {
			fmt.Printf("Found shit\n")
			ReplaceGwRoutes(gwroutes)
		}


	// end netns
	return nil
	})

}
*/