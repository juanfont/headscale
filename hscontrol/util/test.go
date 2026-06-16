package util

import (
	"net/netip"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

var PrefixComparer = cmp.Comparer(func(x, y netip.Prefix) bool {
	return x.Compare(y) == 0
})

var IPComparer = cmp.Comparer(func(x, y netip.Addr) bool {
	return x.Compare(y) == 0
})

var AddrPortComparer = cmp.Comparer(func(x, y netip.AddrPort) bool {
	return x == y
})

func strComparer[T interface{ String() string }]() cmp.Option {
	return cmp.Comparer(func(x, y T) bool {
		return x.String() == y.String()
	})
}

var (
	MkeyComparer = strComparer[key.MachinePublic]()
	NkeyComparer = strComparer[key.NodePublic]()
	DkeyComparer = strComparer[key.DiscoPublic]()
)

var ViewSliceIPProtoComparer = cmp.Comparer(views.SliceEqual[ipproto.Proto])

var Comparers = []cmp.Option{
	IPComparer, PrefixComparer, AddrPortComparer, MkeyComparer, NkeyComparer, DkeyComparer, ViewSliceIPProtoComparer,
}
