package derp

import (
	"cmp"
	"context"
	"encoding/json"
	"hash/crc64"
	"io"
	"maps"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"tailscale.com/tailcfg"
)

func loadDERPMapFromPath(path string) (*tailcfg.DERPMap, error) {
	derpFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer derpFile.Close()
	var derpMap tailcfg.DERPMap
	b, err := io.ReadAll(derpFile)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(b, &derpMap)

	return &derpMap, err
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

// mergeDERPMaps naively merges a list of DERPMaps into a single
// DERPMap, it will _only_ look at the Regions, an integer.
// If a region exists in two of the given DERPMaps, the region
// form the _last_ DERPMap will be preserved.
// An empty DERPMap list will result in a DERPMap with no regions.
func mergeDERPMaps(derpMaps []*tailcfg.DERPMap) *tailcfg.DERPMap {
	result := tailcfg.DERPMap{
		OmitDefaultRegions: false,
		Regions:            map[int]*tailcfg.DERPRegion{},
	}

	for _, derpMap := range derpMaps {
		maps.Copy(result.Regions, derpMap.Regions)
	}

	for id, region := range result.Regions {
		if region == nil {
			delete(result.Regions, id)
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
	ids := make([]int, 0, len(dm.Regions))
	for id := range dm.Regions {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	for _, id := range ids {
		region := dm.Regions[id]
		if len(region.Nodes) == 0 {
			continue
		}

		dm.Regions[id] = shuffleRegionNoClone(region)
	}
}

var crc64Table = crc64.MakeTable(crc64.ISO)

var (
	derpRandomOnce sync.Once
	derpRandomInst *rand.Rand
	derpRandomMu   sync.Mutex
)

func derpRandom() *rand.Rand {
	derpRandomMu.Lock()
	defer derpRandomMu.Unlock()

	derpRandomOnce.Do(func() {
		seed := cmp.Or(viper.GetString("dns.base_domain"), time.Now().String())
		rnd := rand.New(rand.NewSource(0))
		rnd.Seed(int64(crc64.Checksum([]byte(seed), crc64Table)))
		derpRandomInst = rnd
	})
	return derpRandomInst
}

func resetDerpRandomForTesting() {
	derpRandomMu.Lock()
	defer derpRandomMu.Unlock()
	derpRandomOnce = sync.Once{}
	derpRandomInst = nil
}

func shuffleRegionNoClone(r *tailcfg.DERPRegion) *tailcfg.DERPRegion {
	derpRandom().Shuffle(len(r.Nodes), reflect.Swapper(r.Nodes))
	return r
}
