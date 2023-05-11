package util

import (
	"net/netip"
	"reflect"

	"go4.org/netipx"
)

func GetIPPrefixEndpoints(na netip.Prefix) (netip.Addr, netip.Addr) {
	var network, broadcast netip.Addr
	ipRange := netipx.RangeOfPrefix(na)
	network = ipRange.From()
	broadcast = ipRange.To()

	return network, broadcast
}

func StringToIPPrefix(prefixes []string) ([]netip.Prefix, error) {
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

func StringOrPrefixListContains[T string | netip.Prefix](ts []T, t T) bool {
	for _, v := range ts {
		if reflect.DeepEqual(v, t) {
			return true
		}
	}

	return false
}
