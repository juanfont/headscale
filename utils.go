// Codehere is mostly taken from github.com/tailscale/tailscale
// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package headscale

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/nacl/box"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

// Error is used to compare errors as per https://dave.cheney.net/2016/04/07/constant-errors
type Error string

func (e Error) Error() string { return string(e) }

func decode(
	msg []byte,
	v interface{},
	pubKey *wgkey.Key,
	privKey *wgkey.Private,
) error {
	return decodeMsg(msg, v, pubKey, privKey)
}

func decodeMsg(
	msg []byte,
	v interface{},
	pubKey *wgkey.Key,
	privKey *wgkey.Private,
) error {
	decrypted, err := decryptMsg(msg, pubKey, privKey)
	if err != nil {
		return err
	}
	// fmt.Println(string(decrypted))
	if err := json.Unmarshal(decrypted, v); err != nil {
		return fmt.Errorf("response: %v", err)
	}
	return nil
}

func decryptMsg(msg []byte, pubKey *wgkey.Key, privKey *wgkey.Private) ([]byte, error) {
	var nonce [24]byte
	if len(msg) < len(nonce)+1 {
		return nil, fmt.Errorf("response missing nonce, len=%d", len(msg))
	}
	copy(nonce[:], msg)
	msg = msg[len(nonce):]

	pub, pri := (*[32]byte)(pubKey), (*[32]byte)(privKey)
	decrypted, ok := box.Open(nil, msg, &nonce, pub, pri)
	if !ok {
		return nil, fmt.Errorf("cannot decrypt response")
	}
	return decrypted, nil
}

func encode(v interface{}, pubKey *wgkey.Key, privKey *wgkey.Private) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	return encodeMsg(b, pubKey, privKey)
}

func encodeMsg(b []byte, pubKey *wgkey.Key, privKey *wgkey.Private) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	pub, pri := (*[32]byte)(pubKey), (*[32]byte)(privKey)
	msg := box.Seal(nonce[:], b, &nonce, pub, pri)
	return msg, nil
}

func (h *Headscale) getAvailableIP() (*netaddr.IP, error) {
	ipPrefix := h.cfg.IPPrefix

	usedIps, err := h.getUsedIPs()
	if err != nil {
		return nil, err
	}

	// Get the first IP in our prefix
	ip := ipPrefix.IP()

	for {
		if !ipPrefix.Contains(ip) {
			return nil, fmt.Errorf("could not find any suitable IP in %s", ipPrefix)
		}

		// Some OS (including Linux) does not like when IPs ends with 0 or 255, which
		// is typically called network or broadcast. Lets avoid them and continue
		// to look when we get one of those traditionally reserved IPs.
		ipRaw := ip.As4()
		if ipRaw[3] == 0 || ipRaw[3] == 255 {
			ip = ip.Next()
			continue
		}

		if ip.IsZero() &&
			ip.IsLoopback() {
			ip = ip.Next()
			continue
		}

		if !containsIPs(usedIps, ip) {
			return &ip, nil
		}

		ip = ip.Next()
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
				return nil, fmt.Errorf("failed to parse ip from database, %w", err)
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

func stringToIpPrefix(prefixes []string) ([]netaddr.IPPrefix, error) {
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

func containsIpPrefix(prefixes []netaddr.IPPrefix, prefix netaddr.IPPrefix) bool {
	for _, p := range prefixes {
		if prefix == p {
			return true
		}
	}

	return false
}
