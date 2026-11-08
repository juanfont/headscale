package derp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc64"
	"io"
	"maps"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
)

var (
	errEmptyDERPMapFile = errors.New("DERP map file has no regions or homeparams")
	errDERPMapStatus    = errors.New("unexpected HTTP status")
	errDERPURLSyntax    = errors.New("invalid URL syntax")

	ErrRegionIDKey    = errors.New("doesn't match its key")
	ErrRegionNoNodes  = errors.New("must specify at least one node in DERP Region")
	ErrRegionNullNode = errors.New("null node in DERP Region")
	ErrNodeRegionID   = errors.New("doesn't match its region")
)

// ValidateRegion returns what is wrong with region, stored under id in a DERP
// map. Clients look regions up by key and attribute a node's latency to its
// RegionID, so every map must pass, whatever its source. The wording is
// Tailscale SaaS's for a policy derpMap.
func ValidateRegion(id tailcfg.DERPRegionID, region *tailcfg.DERPRegion) []error {
	var errs []error

	if region.RegionID != id {
		errs = append(errs, fmt.Errorf(
			"custom DERP Region %d has RegionID %d that %w", id, region.RegionID, ErrRegionIDKey))
	}

	if len(region.Nodes) == 0 {
		errs = append(errs, fmt.Errorf("%w %d", ErrRegionNoNodes, id))
	}

	for _, node := range region.Nodes {
		if node == nil {
			errs = append(errs, fmt.Errorf("%w %d", ErrRegionNullNode, id))

			continue
		}

		if node.RegionID != id {
			errs = append(errs, fmt.Errorf(
				"custom DERP Region %d has node %q with RegionID %d that %w",
				id, node.Name, node.RegionID, ErrNodeRegionID))
		}
	}

	return errs
}

// validateRegions runs [ValidateRegion] on every region of dm. A null region
// only removes one, so it is not checked.
func validateRegions(dm *tailcfg.DERPMap) error {
	var errs []error

	for _, id := range slices.Sorted(maps.Keys(dm.Regions)) {
		if region := dm.Regions[id]; region != nil {
			errs = append(errs, ValidateRegion(id, region)...)
		}
	}

	return errors.Join(errs...)
}

// loadDERPMapFromPath reads a DERP map file in the format its extension names
// (see [util.UnmarshalByExtStrict]). An unknown key is an error, as SaaS
// rejects one in a policy derpMap, so a misspelt key cannot silently do
// nothing. A map with neither regions nor HomeParams is an error too;
// HomeParams alone is valid, to score regions from other sources. Regions
// must pass [ValidateRegion].
func loadDERPMapFromPath(path string) (*tailcfg.DERPMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading DERP map: %w", err)
	}

	derpMap, err := util.UnmarshalByExtStrict[tailcfg.DERPMap](path, data)
	if err != nil {
		return nil, fmt.Errorf("reading DERP map: %w", err)
	}

	if len(derpMap.Regions) == 0 && derpMap.HomeParams == nil {
		return nil, fmt.Errorf("%w: %s", errEmptyDERPMapFile, path)
	}

	err = validateRegions(&derpMap)
	if err != nil {
		return nil, fmt.Errorf("DERP map %s: %w", path, err)
	}

	return &derpMap, nil
}

func loadDERPMapFromURL(addr url.URL) (*tailcfg.DERPMap, error) {
	ctx, cancel := context.WithTimeout(context.Background(), types.HTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr.String(), nil)
	if err != nil {
		return nil, err
	}

	client := http.Client{
		Timeout: types.HTTPTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// An error page can be JSON that decodes to an empty map.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DERP map %s: %w: %s", addr.Redacted(), errDERPMapStatus, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("DERP map %s: %w", addr.Redacted(), err)
	}

	var derpMap tailcfg.DERPMap

	err = json.Unmarshal(body, &derpMap)
	if err != nil {
		return nil, fmt.Errorf("DERP map %s: %w", addr.Redacted(), err)
	}

	err = validateRegions(&derpMap)
	if err != nil {
		return nil, fmt.Errorf("DERP map %s: %w", addr.Redacted(), err)
	}

	return &derpMap, nil
}

// mergeDERPMaps merges a list of [tailcfg.DERPMap] values into a single
// [tailcfg.DERPMap], looking only at Regions and HomeParams.RegionScore.
// If a region or score exists in two of the given [tailcfg.DERPMap] values, the
// one from the _last_ [tailcfg.DERPMap] will be preserved. HomeParams stays nil
// unless a source sets it.
// An empty [tailcfg.DERPMap] list will result in a [tailcfg.DERPMap] with no regions.
func mergeDERPMaps(derpMaps []*tailcfg.DERPMap) *tailcfg.DERPMap {
	result := tailcfg.DERPMap{
		OmitDefaultRegions: false,
		Regions:            map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{},
	}

	for _, derpMap := range derpMaps {
		if hp := derpMap.HomeParams; hp != nil {
			if result.HomeParams == nil {
				result.HomeParams = &tailcfg.DERPHomeParams{
					RegionScore: map[tailcfg.DERPRegionID]float64{},
				}
			}

			maps.Copy(result.HomeParams.RegionScore, hp.RegionScore)
		}

		// Clone each region: copying the pointer would let a later in-place
		// shuffle alias regions shared with the source map or a previously
		// served map, racing concurrent readers.
		for id, region := range derpMap.Regions {
			// A null region removes one an earlier map added, the documented
			// way to drop a region from derp.urls via derp.paths.
			if region == nil {
				delete(result.Regions, id)
				continue
			}

			result.Regions[id] = region.Clone()
		}
	}

	if result.HomeParams != nil {
		// Clients ignore non-positive scores, and NaN or Inf would fail the
		// JSON encoding of every MapResponse.
		maps.DeleteFunc(result.HomeParams.RegionScore, func(_ tailcfg.DERPRegionID, s float64) bool {
			return s <= 0 || math.IsNaN(s) || math.IsInf(s, 0)
		})
	}

	return &result
}

// ApplyPolicy returns base with a policy derpMap applied the way Tailscale
// SaaS applies one: OmitDefaultRegions drops every base region, a null region
// removes one, and the other regions are added. The policy's HomeParams are
// dropped, as SaaS never sends them; base's are kept.
func ApplyPolicy(base, pol *tailcfg.DERPMap) *tailcfg.DERPMap {
	if base == nil || pol == nil {
		return base
	}

	out := &tailcfg.DERPMap{
		HomeParams: base.HomeParams,
		Regions:    map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{},
	}

	if !pol.OmitDefaultRegions {
		maps.Copy(out.Regions, base.Regions)
	}

	for id, region := range pol.Regions {
		if region == nil {
			delete(out.Regions, id)
			continue
		}

		out.Regions[id] = region.Clone()
	}

	return out
}

// GetDERPMap merges every configured DERP map source. A source that fails to
// load is skipped rather than failing the rest, as a derp.urls server is often
// a third party's: the map always holds what did load, and the error joins
// every failure for the caller to judge. shuffleSeed orders DERP nodes the
// same on every server of a tailnet.
func GetDERPMap(cfg types.DERPConfig, shuffleSeed string) (*tailcfg.DERPMap, error) {
	var (
		derpMaps []*tailcfg.DERPMap
		errs     []error
	)

	if cfg.DERPMap != nil {
		derpMaps = append(derpMaps, cfg.DERPMap)
	}

	for i, u := range cfg.URLs {
		addr, err := url.Parse(string(u))
		if err != nil {
			// The parser's error quotes the URL or parts of it, credentials
			// included.
			errs = append(errs, fmt.Errorf("derp.urls[%d]: %w", i, errDERPURLSyntax))

			continue
		}

		derpMap, err := loadDERPMapFromURL(*addr)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		derpMaps = append(derpMaps, derpMap)
	}

	for _, path := range cfg.Paths {
		derpMap, err := loadDERPMapFromPath(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		derpMaps = append(derpMaps, derpMap)
	}

	derpMap := mergeDERPMaps(derpMaps)
	shuffleDERPMap(derpMap, shuffleSeed)

	return derpMap, errors.Join(errs...)
}

func shuffleDERPMap(dm *tailcfg.DERPMap, seed string) {
	if dm == nil || len(dm.Regions) == 0 {
		return
	}

	// Collect region IDs and sort them to ensure deterministic iteration order.
	// Map iteration order is non-deterministic in Go, which would cause the
	// shuffle to be non-deterministic even with a fixed seed.
	ids := make([]tailcfg.DERPRegionID, 0, len(dm.Regions))
	for id := range dm.Regions {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	// A new generator per call gives the same input the same order. Clients
	// close their home relay when its node order changes, so a refresh that
	// finds no change must not reorder anything.
	rng := rand.New(rand.NewSource(derpShuffleSeed(seed))) //nolint:gosec // weak random is fine for DERP scrambling

	for _, id := range ids {
		region := dm.Regions[id]
		if len(region.Nodes) == 0 {
			continue
		}

		rng.Shuffle(len(region.Nodes), reflect.Swapper(region.Nodes))
	}
}

var crc64Table = crc64.MakeTable(crc64.ISO)

var (
	derpSeed    int64
	derpSeedSet bool
	derpSeedMu  sync.Mutex
)

func derpShuffleSeed(seed string) int64 {
	derpSeedMu.Lock()
	defer derpSeedMu.Unlock()

	if !derpSeedSet {
		seed = cmp.Or(seed, time.Now().String())
		derpSeed = int64(crc64.Checksum([]byte(seed), crc64Table)) //nolint:gosec // only a seed, overflow is harmless
		derpSeedSet = true
	}

	return derpSeed
}

func resetDerpRandomForTesting() {
	derpSeedMu.Lock()
	defer derpSeedMu.Unlock()

	derpSeedSet = false
}
