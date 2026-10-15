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
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
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

// TestMergeDERPMapsNullRemovesRegion pins docs/ref/derp.md's recipe: a later
// map setting a region to null drops it from the result.
func TestMergeDERPMapsNullRemovesRegion(t *testing.T) {
	base := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {RegionID: 1, RegionCode: "nyc"},
			2: {RegionID: 2, RegionCode: "sfo"},
		},
	}
	drop := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: nil}}

	merged := mergeDERPMaps([]*tailcfg.DERPMap{base, drop})

	assert.NotContains(t, merged.Regions, tailcfg.DERPRegionID(1))
	assert.Contains(t, merged.Regions, tailcfg.DERPRegionID(2))
}
