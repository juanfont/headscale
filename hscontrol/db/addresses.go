// Codehere is mostly taken from github.com/tailscale/tailscale
// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package db

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"gorm.io/gorm"
)

var ErrCouldNotAllocateIP = errors.New("could not find any suitable IP")

func (hsdb *HSDatabase) getAvailableIPs() (types.NodeAddresses, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.NodeAddresses, error) {
		return getAvailableIPs(rx, hsdb.ipPrefixes)
	})
}

func getAvailableIPs(rx *gorm.DB, ipPrefixes []netip.Prefix) (types.NodeAddresses, error) {
	var ips types.NodeAddresses
	var err error
	for _, ipPrefix := range ipPrefixes {
		var ip *netip.Addr
		ip, err = getAvailableIP(rx, ipPrefix)
		if err != nil {
			return ips, err
		}
		ips = append(ips, *ip)
	}

	return ips, err
}

func getAvailableIP(rx *gorm.DB, ipPrefix netip.Prefix) (*netip.Addr, error) {
	usedIps, err := getUsedIPs(rx)
	if err != nil {
		return nil, err
	}

	ipPrefixNetworkAddress, ipPrefixBroadcastAddress := util.GetIPPrefixEndpoints(ipPrefix)

	// Get the first IP in our prefix
	ip := ipPrefixNetworkAddress.Next()

	for {
		if !ipPrefix.Contains(ip) {
			return nil, ErrCouldNotAllocateIP
		}

		switch {
		case ip.Compare(ipPrefixBroadcastAddress) == 0:
			fallthrough
		case usedIps.Contains(ip):
			fallthrough
		case ip == netip.Addr{} || ip.IsLoopback():
			ip = ip.Next()

			continue

		default:
			return &ip, nil
		}
	}
}

func getUsedIPs(rx *gorm.DB) (*netipx.IPSet, error) {
	// FIXME: This really deserves a better data model,
	// but this was quick to get running and it should be enough
	// to begin experimenting with a dual stack tailnet.
	var addressesSlices []string
	rx.Model(&types.Node{}).Pluck("ip_addresses", &addressesSlices)

	var ips netipx.IPSetBuilder
	for _, slice := range addressesSlices {
		var machineAddresses types.NodeAddresses
		err := machineAddresses.Scan(slice)
		if err != nil {
			return &netipx.IPSet{}, fmt.Errorf(
				"failed to read ip from database: %w",
				err,
			)
		}

		for _, ip := range machineAddresses {
			ips.Add(ip)
		}
	}

	ipSet, err := ips.IPSet()
	if err != nil {
		return &netipx.IPSet{}, fmt.Errorf(
			"failed to build IP Set: %w",
			err,
		)
	}

	return ipSet, nil
}
