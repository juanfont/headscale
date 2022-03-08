package headscale

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
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
	ctx, cancel := context.WithTimeout(context.Background(), HTTPReadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", addr.String(), nil)
	if err != nil {
		return nil, err
	}

	client := http.Client{
		Timeout: HTTPReadTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
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
		for id, region := range derpMap.Regions {
			result.Regions[id] = region
		}
	}

	return &result
}

func GetDERPMap(cfg DERPConfig) *tailcfg.DERPMap {
	derpMaps := make([]*tailcfg.DERPMap, 0)

	for _, path := range cfg.Paths {
		log.Debug().
			Str("func", "GetDERPMap").
			Str("path", path).
			Msg("Loading DERPMap from path")
		derpMap, err := loadDERPMapFromPath(path)
		if err != nil {
			log.Error().
				Str("func", "GetDERPMap").
				Str("path", path).
				Err(err).
				Msg("Could not load DERP map from path")

			break
		}

		derpMaps = append(derpMaps, derpMap)
	}

	for _, addr := range cfg.URLs {
		derpMap, err := loadDERPMapFromURL(addr)
		log.Debug().
			Str("func", "GetDERPMap").
			Str("url", addr.String()).
			Msg("Loading DERPMap from path")
		if err != nil {
			log.Error().
				Str("func", "GetDERPMap").
				Str("url", addr.String()).
				Err(err).
				Msg("Could not load DERP map from path")

			break
		}

		derpMaps = append(derpMaps, derpMap)
	}

	derpMap := mergeDERPMaps(derpMaps)

	log.Trace().Interface("derpMap", derpMap).Msg("DERPMap loaded")

	if len(derpMap.Regions) == 0 {
		log.Warn().
			Msg("DERP map is empty, not a single DERP map datasource was loaded correctly or contained a region")
	}

	return derpMap
}

func (h *Headscale) scheduledDERPMapUpdateWorker(cancelChan <-chan struct{}) {
	log.Info().
		Dur("frequency", h.cfg.DERP.UpdateFrequency).
		Msg("Setting up a DERPMap update worker")
	ticker := time.NewTicker(h.cfg.DERP.UpdateFrequency)

	for {
		select {
		case <-cancelChan:
			return

		case <-ticker.C:
			log.Info().Msg("Fetching DERPMap updates")
			h.DERPMap = GetDERPMap(h.cfg.DERP)
			h.DERPMap.Regions[h.DERPServer.region.RegionID] = &h.DERPServer.region

			namespaces, err := h.ListNamespaces()
			if err != nil {
				log.Error().
					Err(err).
					Msg("Failed to fetch namespaces")
			}

			for _, namespace := range namespaces {
				h.setLastStateChangeToNow(namespace.Name)
			}
		}
	}
}
