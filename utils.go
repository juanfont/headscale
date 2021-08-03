// Codehere is mostly taken from github.com/tailscale/tailscale
// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package headscale

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
	"inet.af/netaddr"
	"tailscale.com/types/wgkey"
)

// Error is used to compare errors as per https://dave.cheney.net/2016/04/07/constant-errors
type Error string

func (e Error) Error() string { return string(e) }

func decode(msg []byte, v interface{}, pubKey *wgkey.Key, privKey *wgkey.Private) error {
	return decodeMsg(msg, v, pubKey, privKey)
}

func decodeMsg(msg []byte, v interface{}, pubKey *wgkey.Key, privKey *wgkey.Private) error {
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

	// for _, ip := range usedIps {
	// 	nextIP := ip.Next()

	// 	if !containsIPs(usedIps, nextIP) && ipPrefix.Contains(nextIP) {
	// 		return &nextIP, nil
	// 	}
	// }

	// // If there are no IPs in use, we are starting fresh and
	// // can issue IPs from the beginning of the prefix.
	// ip := ipPrefix.IP()
	// return &ip, nil

	// return nil, fmt.Errorf("failed to find any available IP in %s", ipPrefix)

	// Get the first IP in our prefix
	ip := ipPrefix.IP()

	for {
		if !ipPrefix.Contains(ip) {
			return nil, fmt.Errorf("could not find any suitable IP in %s", ipPrefix)
		}

		if ip.IsZero() &&
			ip.IsLoopback() {
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
