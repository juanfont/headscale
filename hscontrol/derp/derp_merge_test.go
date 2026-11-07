package derp

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestGetDERPMapCarriesHomeParams pins that RegionScore set in a derp.paths
// file reaches clients (#2918). A file may hold scores alone: region 1 comes
// from another source and 999 is the embedded region app.go adds after the
// merge. Without scores HomeParams stays nil, so the MapResponse is unchanged
// for everyone who does not opt in.
func TestGetDERPMapCarriesHomeParams(t *testing.T) {
	base := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {RegionID: 1, RegionCode: "nyc"},
		},
	}

	path := filepath.Join(t.TempDir(), "derp.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`homeparams:
  regionscore:
    1: 4
    999: 0.5
`), 0o600))

	got, err := GetDERPMap(types.DERPConfig{DERPMap: base}, "")
	require.NoError(t, err)
	assert.Nil(t, got.HomeParams)

	got, err = GetDERPMap(types.DERPConfig{DERPMap: base, Paths: []string{path}}, "")
	require.NoError(t, err)
	require.NotNil(t, got.HomeParams)
	assert.Equal(t,
		map[tailcfg.DERPRegionID]float64{1: 4, 999: 0.5},
		got.HomeParams.RegionScore,
	)
}

// TestMergeDERPMapsHomeParams mirrors region merging: a later map's score for
// a region replaces an earlier one, and other scores survive maps that set
// none. Scores clients ignore or JSON cannot encode are dropped.
func TestMergeDERPMapsHomeParams(t *testing.T) {
	first := &tailcfg.DERPMap{HomeParams: &tailcfg.DERPHomeParams{
		RegionScore: map[tailcfg.DERPRegionID]float64{1: 2, 2: 3},
	}}
	none := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: {RegionID: 1},
	}}
	empty := &tailcfg.DERPMap{HomeParams: &tailcfg.DERPHomeParams{}}
	invalid := &tailcfg.DERPMap{HomeParams: &tailcfg.DERPHomeParams{
		RegionScore: map[tailcfg.DERPRegionID]float64{
			3: 0, 4: -1, 5: math.NaN(), 6: math.Inf(1),
		},
	}}
	second := &tailcfg.DERPMap{HomeParams: &tailcfg.DERPHomeParams{
		RegionScore: map[tailcfg.DERPRegionID]float64{1: 0.5},
	}}

	merged := mergeDERPMaps([]*tailcfg.DERPMap{first, none, empty, invalid, second})

	require.NotNil(t, merged.HomeParams)
	assert.Equal(t,
		map[tailcfg.DERPRegionID]float64{1: 0.5, 2: 3},
		merged.HomeParams.RegionScore,
	)

	merged.HomeParams.RegionScore[2] = 9
	assert.Equal(t,
		map[tailcfg.DERPRegionID]float64{1: 2, 2: 3},
		first.HomeParams.RegionScore,
		"merged scores must not alias a source map",
	)
}
