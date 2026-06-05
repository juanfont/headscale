package derp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
)

// TestMergeDERPMapsClonesRegions ensures merged DERP maps own their regions
// rather than aliasing the source pointers, so a later in-place node shuffle
// cannot mutate a shared or previously served map.
func TestMergeDERPMapsClonesRegions(t *testing.T) {
	src := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "a"}, {Name: "b"}}},
		},
	}

	merged := mergeDERPMaps([]*tailcfg.DERPMap{src})

	assert.NotSame(t, src.Regions[1], merged.Regions[1],
		"merged region must not alias the source region pointer")

	merged.Regions[1].Nodes[0] = &tailcfg.DERPNode{Name: "mutated"}
	assert.Equal(t, "a", src.Regions[1].Nodes[0].Name,
		"source region was mutated through a shared pointer")
}
