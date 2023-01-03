// Codehere is mostly taken from github.com/tailscale/tailscale
// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package headscale

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	ErrCannotDecryptResponse = Error("cannot decrypt response")
	ErrCouldNotAllocateIP    = Error("could not find any suitable IP")

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

	PermissionFallback = 0o700

	ZstdCompression = "zstd"
)

var NodePublicKeyRegex = regexp.MustCompile("nodekey:[a-fA-F0-9]+")

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
	log.Trace().
		Str("pubkey", pubKey.ShortString()).
		Int("length", len(msg)).
		Msg("Trying to decrypt")

	decrypted, ok := privKey.OpenFrom(*pubKey, msg)
	if !ok {
		return ErrCannotDecryptResponse
	}

	if err := json.Unmarshal(decrypted, output); err != nil {
		return err
	}

	return nil
}

func (h *Headscale) getAvailableIPs() (MachineAddresses, error) {
	var ips MachineAddresses
	var err error
	ipPrefixes := h.cfg.IPPrefixes
	for _, ipPrefix := range ipPrefixes {
		var ip *netip.Addr
		ip, err = h.getAvailableIP(ipPrefix)
		if err != nil {
			return ips, err
		}
		ips = append(ips, *ip)
	}

	return ips, err
}

func GetIPPrefixEndpoints(na netip.Prefix) (netip.Addr, netip.Addr) {
	var network, broadcast netip.Addr
	ipRange := netipx.RangeOfPrefix(na)
	network = ipRange.From()
	broadcast = ipRange.To()

	return network, broadcast
}

func (h *Headscale) getAvailableIP(ipPrefix netip.Prefix) (*netip.Addr, error) {
	usedIps, err := h.getUsedIPs()
	if err != nil {
		return nil, err
	}

	ipPrefixNetworkAddress, ipPrefixBroadcastAddress := GetIPPrefixEndpoints(ipPrefix)

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

func (h *Headscale) getUsedIPs() (*netipx.IPSet, error) {
	// FIXME: This really deserves a better data model,
	// but this was quick to get running and it should be enough
	// to begin experimenting with a dual stack tailnet.
	var addressesSlices []string
	h.db.Model(&Machine{}).Pluck("ip_addresses", &addressesSlices)

	var ips netipx.IPSetBuilder
	for _, slice := range addressesSlices {
		var machineAddresses MachineAddresses
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

func stringToIPPrefix(prefixes []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, len(prefixes))

	for index, prefixStr := range prefixes {
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return []netip.Prefix{}, err
		}

		result[index] = prefix
	}

	return result, nil
}

func containsStr(ts []string, t string) bool {
	for _, v := range ts {
		if v == t {
			return true
		}
	}

	return false
}

func contains[T string | netip.Prefix](ts []T, t T) bool {
	for _, v := range ts {
		if reflect.DeepEqual(v, t) {
			return true
		}
	}

	return false
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)

	// Note that err == nil only if we read len(b) bytes.
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}

	return bytes, nil
}

// GenerateRandomStringURLSafe returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomStringURLSafe(n int) (string, error) {
	b, err := GenerateRandomBytes(n)

	return base64.RawURLEncoding.EncodeToString(b), err
}

// GenerateRandomStringDNSSafe returns a DNS-safe
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomStringDNSSafe(size int) (string, error) {
	var str string
	var err error
	for len(str) < size {
		str, err = GenerateRandomStringURLSafe(size)
		if err != nil {
			return "", err
		}
		str = strings.ToLower(
			strings.ReplaceAll(strings.ReplaceAll(str, "_", ""), "-", ""),
		)
	}

	return str[:size], nil
}

func IsStringInSlice(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}

	return false
}

func AbsolutePathFromConfigPath(path string) string {
	// If a relative path is provided, prefix it with the directory where
	// the config file was found.
	if (path != "") && !strings.HasPrefix(path, string(os.PathSeparator)) {
		dir, _ := filepath.Split(viper.ConfigFileUsed())
		if dir != "" {
			path = filepath.Join(dir, path)
		}
	}

	return path
}

func GetFileMode(key string) fs.FileMode {
	modeStr := viper.GetString(key)

	mode, err := strconv.ParseUint(modeStr, Base8, BitSize64)
	if err != nil {
		return PermissionFallback
	}

	return fs.FileMode(mode)
}
