// Codehere is mostly taken from github.com/tailscale/tailscale
// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package headscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/rs/zerolog/log"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	errCannotDecryptReponse = Error("cannot decrypt response")
	errCouldNotAllocateIP   = Error("could not find any suitable IP")

	// These constants are copied from the upstream tailscale.com/types/key
	// library, because they are not exported.
	// https://github.com/tailscale/tailscale/tree/main/types/key

	// nodePublicHexPrefix is the prefix used to identify a
	// hex-encoded node public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	nodePublicHexPrefix = "nodekey:"

	// machinePublicHexPrefix is the prefix used to identify a
	// hex-encoded machine public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	machinePublicHexPrefix = "mkey:"

	// discoPublicHexPrefix is the prefix used to identify a
	// hex-encoded disco public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	discoPublicHexPrefix = "discokey:"

	// privateKey prefix.
	privateHexPrefix = "privkey:"
)

func MachinePublicKeyStripPrefix(machineKey key.MachinePublic) string {
	return strings.TrimPrefix(machineKey.String(), machinePublicHexPrefix)
}

func NodePublicKeyStripPrefix(nodeKey key.NodePublic) string {
	return strings.TrimPrefix(nodeKey.String(), nodePublicHexPrefix)
}

func DiscoPublicKeyStripPrefix(discoKey key.DiscoPublic) string {
	return strings.TrimPrefix(discoKey.String(), discoPublicHexPrefix)
}

func MachinePublicKeyEnsurePrefix(machineKey string) string {
	if !strings.HasPrefix(machineKey, machinePublicHexPrefix) {
		return machinePublicHexPrefix + machineKey
	}

	return machineKey
}

func NodePublicKeyEnsurePrefix(nodeKey string) string {
	if !strings.HasPrefix(nodeKey, nodePublicHexPrefix) {
		return nodePublicHexPrefix + nodeKey
	}

	return nodeKey
}

func DiscoPublicKeyEnsurePrefix(discoKey string) string {
	if !strings.HasPrefix(discoKey, discoPublicHexPrefix) {
		return discoPublicHexPrefix + discoKey
	}

	return discoKey
}

func PrivateKeyEnsurePrefix(privateKey string) string {
	if !strings.HasPrefix(privateKey, privateHexPrefix) {
		return privateHexPrefix + privateKey
	}

	return privateKey
}

// Error is used to compare errors as per https://dave.cheney.net/2016/04/07/constant-errors
type Error string

func (e Error) Error() string { return string(e) }

func decode(
	msg []byte,
	output interface{},
	pubKey *key.MachinePublic,
	privKey *key.MachinePrivate,
) error {
	log.Trace().Int("length", len(msg)).Msg("Trying to decrypt")

	decrypted, ok := privKey.OpenFrom(*pubKey, msg)
	if !ok {
		return errCannotDecryptReponse
	}

	if err := json.Unmarshal(decrypted, output); err != nil {
		return err
	}

	return nil
}

func encode(
	v interface{},
	pubKey *key.MachinePublic,
	privKey *key.MachinePrivate,
) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	return privKey.SealTo(*pubKey, b), nil
}

func (h *Headscale) getAvailableIP() (*netaddr.IP, error) {
	ipPrefix := h.cfg.IPPrefix

	usedIps, err := h.getUsedIPs()
	if err != nil {
		return nil, err
	}

	ipPrefixNetworkAddress, ipPrefixBroadcastAddress := func() (netaddr.IP, netaddr.IP) {
		ipRange := ipPrefix.Range()
		return ipRange.From(), ipRange.To()
	}()

	// Get the first IP in our prefix
	ip := ipPrefixNetworkAddress.Next()

	for {
		if !ipPrefix.Contains(ip) {
			return nil, errCouldNotAllocateIP
		}

		switch {
		case ip.Compare(ipPrefixBroadcastAddress) == 0:
			fallthrough
		case containsIPs(usedIps, ip):
			fallthrough
		case ip.IsZero() || ip.IsLoopback():
			ip = ip.Next()

			continue

		default:
			return &ip, nil
		}
	}
}

func (h *Headscale) getUsedIPs() ([]netaddr.IP, error) {
	var addresses []string
	h.db.Model(&Machine{}).Pluck("ip_address", &addresses)

	ips := make([]netaddr.IP, len(addresses))
	for index, addr := range addresses {
		if addr != "" {
			ip, err := netaddr.ParseIP(addr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ip from database: %w", err)
			}

			ips[index] = ip
		}
	}

	return ips, nil
}

func containsIPs(ips []netaddr.IP, ip netaddr.IP) bool {
	for _, v := range ips {
		if v == ip {
			return true
		}
	}

	return false
}

func tailNodesToString(nodes []*tailcfg.Node) string {
	temp := make([]string, len(nodes))

	for index, node := range nodes {
		temp[index] = node.Name
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

func tailMapResponseToString(resp tailcfg.MapResponse) string {
	return fmt.Sprintf(
		"{ Node: %s, Peers: %s }",
		resp.Node.Name,
		tailNodesToString(resp.Peers),
	)
}

func GrpcSocketDialer(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer

	return d.DialContext(ctx, "unix", addr)
}

func ipPrefixToString(prefixes []netaddr.IPPrefix) []string {
	result := make([]string, len(prefixes))

	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}

	return result
}

func stringToIPPrefix(prefixes []string) ([]netaddr.IPPrefix, error) {
	result := make([]netaddr.IPPrefix, len(prefixes))

	for index, prefixStr := range prefixes {
		prefix, err := netaddr.ParseIPPrefix(prefixStr)
		if err != nil {
			return []netaddr.IPPrefix{}, err
		}

		result[index] = prefix
	}

	return result, nil
}

func containsIPPrefix(prefixes []netaddr.IPPrefix, prefix netaddr.IPPrefix) bool {
	for _, p := range prefixes {
		if prefix == p {
			return true
		}
	}

	return false
}
