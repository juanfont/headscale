package derp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc64"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/spf13/viper"
	"tailscale.com/tailcfg"
)

var errEmptyDERPMapFile = errors.New("DERP map file has no regions (YAML keys are lowercased Go field names, e.g. regionid)")

// loadDERPMapFromPath reads a DERP map file in the format its extension names
// (see [util.UnmarshalByExt]). A map with no regions is an error: unknown keys
// decode to nothing, e.g. YAML written with JSON's field names.
func loadDERPMapFromPath(path string) (*tailcfg.DERPMap, error) {
	derpMap, err := util.ReadFileByExt[tailcfg.DERPMap](path)
	if err != nil {
		return nil, fmt.Errorf("reading DERP map: %w", err)
	}

	if len(derpMap.Regions) == 0 {
		return nil, fmt.Errorf("%w: %s", errEmptyDERPMapFile, path)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var derpMap tailcfg.DERPMap

	err = json.Unmarshal(body, &derpMap)

	return &derpMap, err
}

// mergeDERPMaps naively merges a list of [tailcfg.DERPMap] values into a single
// [tailcfg.DERPMap], it will _only_ look at the Regions, an integer.
// If a region exists in two of the given [tailcfg.DERPMap] values, the region
// form the _last_ [tailcfg.DERPMap] will be preserved.
// An empty [tailcfg.DERPMap] list will result in a [tailcfg.DERPMap] with no regions.
func mergeDERPMaps(derpMaps []*tailcfg.DERPMap) *tailcfg.DERPMap {
	result := tailcfg.DERPMap{
		OmitDefaultRegions: false,
		Regions:            map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{},
	}

	for _, derpMap := range derpMaps {
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

	return &result
}

func GetDERPMap(cfg types.DERPConfig) (*tailcfg.DERPMap, error) {
	var derpMaps []*tailcfg.DERPMap
	if cfg.DERPMap != nil {
		derpMaps = append(derpMaps, cfg.DERPMap)
	}

	for _, addr := range cfg.URLs {
		derpMap, err := loadDERPMapFromURL(addr)
		if err != nil {
			return nil, err
		}

		derpMaps = append(derpMaps, derpMap)
	}

	for _, path := range cfg.Paths {
		derpMap, err := loadDERPMapFromPath(path)
		if err != nil {
			return nil, err
		}

		derpMaps = append(derpMaps, derpMap)
	}

	derpMap := mergeDERPMaps(derpMaps)
	shuffleDERPMap(derpMap)

	return derpMap, nil
}

func shuffleDERPMap(dm *tailcfg.DERPMap) {
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
	rng := rand.New(rand.NewSource(derpShuffleSeed())) //nolint:gosec // weak random is fine for DERP scrambling

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

func derpShuffleSeed() int64 {
	derpSeedMu.Lock()
	defer derpSeedMu.Unlock()

	if !derpSeedSet {
		seed := cmp.Or(viper.GetString("dns.base_domain"), time.Now().String())
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
