package types

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/util"
)

func TestPrefixMap(t *testing.T) {
	ipp := func(s string) IPPrefix { return IPPrefix(netip.MustParsePrefix(s)) }

	// TODO(kradalby): Remove when we have gotten rid of IPPrefix type
	prefixComparer := cmp.Comparer(func(x, y IPPrefix) bool {
		return x == y
	})

	tests := []struct {
		rs   Routes
		want map[IPPrefix][]Route
	}{
		{
			rs: Routes{
				Route{
					Prefix: ipp("10.0.0.0/24"),
				},
			},
			want: map[IPPrefix][]Route{
				ipp("10.0.0.0/24"): Routes{
					Route{
						Prefix: ipp("10.0.0.0/24"),
					},
				},
			},
		},
		{
			rs: Routes{
				Route{
					Prefix: ipp("10.0.0.0/24"),
				},
				Route{
					Prefix: ipp("10.0.1.0/24"),
				},
			},
			want: map[IPPrefix][]Route{
				ipp("10.0.0.0/24"): Routes{
					Route{
						Prefix: ipp("10.0.0.0/24"),
					},
				},
				ipp("10.0.1.0/24"): Routes{
					Route{
						Prefix: ipp("10.0.1.0/24"),
					},
				},
			},
		},
		{
			rs: Routes{
				Route{
					Prefix:  ipp("10.0.0.0/24"),
					Enabled: true,
				},
				Route{
					Prefix:  ipp("10.0.0.0/24"),
					Enabled: false,
				},
			},
			want: map[IPPrefix][]Route{
				ipp("10.0.0.0/24"): Routes{
					Route{
						Prefix:  ipp("10.0.0.0/24"),
						Enabled: true,
					},
					Route{
						Prefix:  ipp("10.0.0.0/24"),
						Enabled: false,
					},
				},
			},
		},
	}

	for idx, tt := range tests {
		t.Run(fmt.Sprintf("test-%d", idx), func(t *testing.T) {
			got := tt.rs.PrefixMap()
			if diff := cmp.Diff(tt.want, got, prefixComparer, util.MkeyComparer, util.NkeyComparer, util.DkeyComparer); diff != "" {
				t.Errorf("PrefixMap() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
