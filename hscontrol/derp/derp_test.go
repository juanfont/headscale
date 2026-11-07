package derp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestShuffleDERPMapDeterministic(t *testing.T) {
	tests := []struct {
		name       string
		baseDomain string
		derpMap    *tailcfg.DERPMap
		expected   *tailcfg.DERPMap
	}{
		{
			name:       "single region with 4 nodes",
			baseDomain: "test1.example.com",
			derpMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					1: {
						RegionID:   1,
						RegionCode: "nyc",
						RegionName: "New York City",
						Nodes: []*tailcfg.DERPNode{
							{Name: "1f", RegionID: 1, HostName: "derp1f.tailscale.com"},
							{Name: "1g", RegionID: 1, HostName: "derp1g.tailscale.com"},
							{Name: "1h", RegionID: 1, HostName: "derp1h.tailscale.com"},
							{Name: "1i", RegionID: 1, HostName: "derp1i.tailscale.com"},
						},
					},
				},
			},
			expected: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					1: {
						RegionID:   1,
						RegionCode: "nyc",
						RegionName: "New York City",
						Nodes: []*tailcfg.DERPNode{
							{Name: "1g", RegionID: 1, HostName: "derp1g.tailscale.com"},
							{Name: "1f", RegionID: 1, HostName: "derp1f.tailscale.com"},
							{Name: "1i", RegionID: 1, HostName: "derp1i.tailscale.com"},
							{Name: "1h", RegionID: 1, HostName: "derp1h.tailscale.com"},
						},
					},
				},
			},
		},
		{
			name:       "multiple regions with nodes",
			baseDomain: "test2.example.com",
			derpMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					10: {
						RegionID:   10,
						RegionCode: "sea",
						RegionName: "Seattle",
						Nodes: []*tailcfg.DERPNode{
							{Name: "10b", RegionID: 10, HostName: "derp10b.tailscale.com"},
							{Name: "10c", RegionID: 10, HostName: "derp10c.tailscale.com"},
							{Name: "10d", RegionID: 10, HostName: "derp10d.tailscale.com"},
						},
					},
					2: {
						RegionID:   2,
						RegionCode: "sfo",
						RegionName: "San Francisco",
						Nodes: []*tailcfg.DERPNode{
							{Name: "2d", RegionID: 2, HostName: "derp2d.tailscale.com"},
							{Name: "2e", RegionID: 2, HostName: "derp2e.tailscale.com"},
							{Name: "2f", RegionID: 2, HostName: "derp2f.tailscale.com"},
						},
					},
				},
			},
			expected: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					10: {
						RegionID:   10,
						RegionCode: "sea",
						RegionName: "Seattle",
						Nodes: []*tailcfg.DERPNode{
							{Name: "10d", RegionID: 10, HostName: "derp10d.tailscale.com"},
							{Name: "10c", RegionID: 10, HostName: "derp10c.tailscale.com"},
							{Name: "10b", RegionID: 10, HostName: "derp10b.tailscale.com"},
						},
					},
					2: {
						RegionID:   2,
						RegionCode: "sfo",
						RegionName: "San Francisco",
						Nodes: []*tailcfg.DERPNode{
							{Name: "2d", RegionID: 2, HostName: "derp2d.tailscale.com"},
							{Name: "2e", RegionID: 2, HostName: "derp2e.tailscale.com"},
							{Name: "2f", RegionID: 2, HostName: "derp2f.tailscale.com"},
						},
					},
				},
			},
		},
		{
			name:       "large region with many nodes",
			baseDomain: "test3.example.com",
			derpMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					4: {
						RegionID:   4,
						RegionCode: "fra",
						RegionName: "Frankfurt",
						Nodes: []*tailcfg.DERPNode{
							{Name: "4f", RegionID: 4, HostName: "derp4f.tailscale.com"},
							{Name: "4g", RegionID: 4, HostName: "derp4g.tailscale.com"},
							{Name: "4h", RegionID: 4, HostName: "derp4h.tailscale.com"},
							{Name: "4i", RegionID: 4, HostName: "derp4i.tailscale.com"},
						},
					},
				},
			},
			expected: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					4: {
						RegionID:   4,
						RegionCode: "fra",
						RegionName: "Frankfurt",
						Nodes: []*tailcfg.DERPNode{
							{Name: "4f", RegionID: 4, HostName: "derp4f.tailscale.com"},
							{Name: "4h", RegionID: 4, HostName: "derp4h.tailscale.com"},
							{Name: "4g", RegionID: 4, HostName: "derp4g.tailscale.com"},
							{Name: "4i", RegionID: 4, HostName: "derp4i.tailscale.com"},
						},
					},
				},
			},
		},
		{
			name:       "same region different base domain",
			baseDomain: "different.example.com",
			derpMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					4: {
						RegionID:   4,
						RegionCode: "fra",
						RegionName: "Frankfurt",
						Nodes: []*tailcfg.DERPNode{
							{Name: "4f", RegionID: 4, HostName: "derp4f.tailscale.com"},
							{Name: "4g", RegionID: 4, HostName: "derp4g.tailscale.com"},
							{Name: "4h", RegionID: 4, HostName: "derp4h.tailscale.com"},
							{Name: "4i", RegionID: 4, HostName: "derp4i.tailscale.com"},
						},
					},
				},
			},
			expected: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					4: {
						RegionID:   4,
						RegionCode: "fra",
						RegionName: "Frankfurt",
						Nodes: []*tailcfg.DERPNode{
							{Name: "4g", RegionID: 4, HostName: "derp4g.tailscale.com"},
							{Name: "4i", RegionID: 4, HostName: "derp4i.tailscale.com"},
							{Name: "4f", RegionID: 4, HostName: "derp4f.tailscale.com"},
							{Name: "4h", RegionID: 4, HostName: "derp4h.tailscale.com"},
						},
					},
				},
			},
		},
		{
			name:       "same dataset with another base domain",
			baseDomain: "another.example.com",
			derpMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					4: {
						RegionID:   4,
						RegionCode: "fra",
						RegionName: "Frankfurt",
						Nodes: []*tailcfg.DERPNode{
							{Name: "4f", RegionID: 4, HostName: "derp4f.tailscale.com"},
							{Name: "4g", RegionID: 4, HostName: "derp4g.tailscale.com"},
							{Name: "4h", RegionID: 4, HostName: "derp4h.tailscale.com"},
							{Name: "4i", RegionID: 4, HostName: "derp4i.tailscale.com"},
						},
					},
				},
			},
			expected: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					4: {
						RegionID:   4,
						RegionCode: "fra",
						RegionName: "Frankfurt",
						Nodes: []*tailcfg.DERPNode{
							{Name: "4h", RegionID: 4, HostName: "derp4h.tailscale.com"},
							{Name: "4f", RegionID: 4, HostName: "derp4f.tailscale.com"},
							{Name: "4g", RegionID: 4, HostName: "derp4g.tailscale.com"},
							{Name: "4i", RegionID: 4, HostName: "derp4i.tailscale.com"},
						},
					},
				},
			},
		},
		{
			name:       "same dataset with yet another base domain",
			baseDomain: "yetanother.example.com",
			derpMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					4: {
						RegionID:   4,
						RegionCode: "fra",
						RegionName: "Frankfurt",
						Nodes: []*tailcfg.DERPNode{
							{Name: "4f", RegionID: 4, HostName: "derp4f.tailscale.com"},
							{Name: "4g", RegionID: 4, HostName: "derp4g.tailscale.com"},
							{Name: "4h", RegionID: 4, HostName: "derp4h.tailscale.com"},
							{Name: "4i", RegionID: 4, HostName: "derp4i.tailscale.com"},
						},
					},
				},
			},
			expected: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					4: {
						RegionID:   4,
						RegionCode: "fra",
						RegionName: "Frankfurt",
						Nodes: []*tailcfg.DERPNode{
							{Name: "4i", RegionID: 4, HostName: "derp4i.tailscale.com"},
							{Name: "4h", RegionID: 4, HostName: "derp4h.tailscale.com"},
							{Name: "4f", RegionID: 4, HostName: "derp4f.tailscale.com"},
							{Name: "4g", RegionID: 4, HostName: "derp4g.tailscale.com"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetDerpRandomForTesting()

			testMap := tt.derpMap.View().AsStruct()
			shuffleDERPMap(testMap, tt.baseDomain)

			if diff := cmp.Diff(tt.expected, testMap); diff != "" {
				t.Errorf("Shuffled DERP map doesn't match expected (-expected +actual):\n%s", diff)
			}
		})
	}
}

// TestGetDERPMapKeepsOrderAcrossRefreshes: clients close their home relay when
// its node order changes, so a refresh of the same input must keep the order.
func TestGetDERPMapKeepsOrderAcrossRefreshes(t *testing.T) {
	resetDerpRandomForTesting()

	source := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}

	for id := range tailcfg.DERPRegionID(5) {
		region := &tailcfg.DERPRegion{RegionID: id + 1}
		for _, name := range []string{"a", "b", "c", "d", "e"} {
			region.Nodes = append(region.Nodes, &tailcfg.DERPNode{Name: name, RegionID: id + 1})
		}

		source.Regions[id+1] = region
	}

	first, err := GetDERPMap(types.DERPConfig{DERPMap: source}, "stable.example.com")
	require.NoError(t, err)

	for range 5 {
		next, err := GetDERPMap(types.DERPConfig{DERPMap: source}, "stable.example.com")
		require.NoError(t, err)

		if diff := cmp.Diff(first, next); diff != "" {
			t.Fatalf("refresh changed the DERP map (-first +next):\n%s", diff)
		}
	}
}

func TestShuffleDERPMapEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		derpMap *tailcfg.DERPMap
	}{
		{
			name:    "nil derp map",
			derpMap: nil,
		},
		{
			name: "empty derp map",
			derpMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{},
			},
		},
		{
			name: "region with no nodes",
			derpMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					1: {
						RegionID:   1,
						RegionCode: "empty",
						RegionName: "Empty Region",
						Nodes:      []*tailcfg.DERPNode{},
					},
				},
			},
		},
		{
			name: "region with single node",
			derpMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					1: {
						RegionID:   1,
						RegionCode: "single",
						RegionName: "Single Node Region",
						Nodes: []*tailcfg.DERPNode{
							{Name: "1a", RegionID: 1, HostName: "derp1a.tailscale.com"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shuffleDERPMap(tt.derpMap, "")
		})
	}
}

func TestShuffleDERPMapWithoutBaseDomain(t *testing.T) {
	resetDerpRandomForTesting()

	derpMap := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Test Region",
				Nodes: []*tailcfg.DERPNode{
					{Name: "1a", RegionID: 1, HostName: "derp1a.test.com"},
					{Name: "1b", RegionID: 1, HostName: "derp1b.test.com"},
					{Name: "1c", RegionID: 1, HostName: "derp1c.test.com"},
					{Name: "1d", RegionID: 1, HostName: "derp1d.test.com"},
				},
			},
		},
	}

	original := derpMap.View().AsStruct()
	shuffleDERPMap(derpMap, "")

	if len(derpMap.Regions) != 1 || len(derpMap.Regions[1].Nodes) != 4 {
		t.Error("Shuffle corrupted DERP map structure")
	}

	originalNodes := make(map[string]bool)
	for _, node := range original.Regions[1].Nodes {
		originalNodes[node.Name] = true
	}

	shuffledNodes := make(map[string]bool)
	for _, node := range derpMap.Regions[1].Nodes {
		shuffledNodes[node.Name] = true
	}

	if diff := cmp.Diff(originalNodes, shuffledNodes); diff != "" {
		t.Errorf("Shuffle changed node set (-original +shuffled):\n%s", diff)
	}
}

// TestLoadDERPMapFromPath covers each file format and the silent-empty trap:
// keys the decoder doesn't know decode to nothing.
func TestLoadDERPMapFromPath(t *testing.T) {
	want := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			999: {
				RegionID:   999,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{Name: "999a", RegionID: 999, HostName: "derp.test", DERPPort: 443, InsecureForTests: true},
				},
			},
		},
		HomeParams: &tailcfg.DERPHomeParams{
			RegionScore: map[tailcfg.DERPRegionID]float64{999: 0.5},
		},
	}

	tailcfgJSON, err := json.Marshal(want)
	require.NoError(t, err)

	yamlMap := `regions:
  999:
    regionid: 999
    regioncode: test
    nodes:
      - name: 999a
        regionid: 999
        hostname: derp.test
        derpport: 443
        insecurefortests: true
homeparams:
  regionscore:
    999: 0.5
`

	tests := []struct {
		name    string
		file    string
		content string
		wantErr bool
	}{
		{name: "yaml", file: "derp.yaml", content: yamlMap},
		{name: "yml", file: "derp.yml", content: yamlMap},
		{
			name:    "flow-style yaml",
			file:    "derp.yaml",
			content: "{regions: {999: {regionid: 999, regioncode: test, nodes: [{name: 999a, regionid: 999, hostname: derp.test, derpport: 443, insecurefortests: true}]}}, homeparams: {regionscore: {999: 0.5}}}",
		},
		{name: "tailcfg json", file: "derp.json", content: string(tailcfgJSON)},
		{name: "tailcfg json with comments and trailing comma", file: "derp.json", content: "// test map\n" + strings.TrimSuffix(string(tailcfgJSON), "}") + ",}"},
		{name: "tailcfg hujson", file: "derp.hujson", content: "// test map\n" + string(tailcfgJSON)},
		{name: "tailcfg json with unterminated comment", file: "derp.json", content: string(tailcfgJSON) + " /*", wantErr: true},
		{name: "json as yaml decodes to nothing", file: "derp.yaml", content: string(tailcfgJSON), wantErr: true},
		{name: "misspelt yaml key", file: "derp.yaml", content: "homeparams: {regionscores: {999: 0.5}}", wantErr: true},
		{name: "unknown json key", file: "derp.json", content: `{"HomeParams": {"Bogus": 1}}`, wantErr: true},
		{name: "region id not its key", file: "derp.json", content: `{"Regions": {"999": {"RegionID": 998, "Nodes": [{"Name": "a", "RegionID": 999}]}}}`, wantErr: true},
		{name: "node in another region", file: "derp.json", content: `{"Regions": {"999": {"RegionID": 999, "Nodes": [{"Name": "a", "RegionID": 998}]}}}`, wantErr: true},
		{name: "region without nodes", file: "derp.json", content: `{"Regions": {"999": {"RegionID": 999}}}`, wantErr: true},
		{name: "null node", file: "derp.json", content: `{"Regions": {"999": {"RegionID": 999, "Nodes": [null]}}}`, wantErr: true},
		{name: "empty", file: "derp.yaml", content: "", wantErr: true},
		{name: "no extension", file: "derp", content: yamlMap, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.file)
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

			got, err := loadDERPMapFromPath(path)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("loadDERPMapFromPath() mismatch (-want +got):\n%s", diff)
			}
		})
	}

	// A null region removes one and has nothing to check.
	path := filepath.Join(t.TempDir(), "drop.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"Regions": {"1": null}}`), 0o600))

	_, err = loadDERPMapFromPath(path)
	require.NoError(t, err)
}

// TestLoadDERPMapFromURLValidates pins that a fetched map meets the region
// rules a derp.paths file does.
func TestLoadDERPMapFromURLValidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Regions": {"1": {"RegionID": 2, "Nodes": [{"Name": "a", "RegionID": 1}]}}}`))
	}))
	defer srv.Close()

	addr, err := url.Parse(srv.URL)
	require.NoError(t, err)

	_, err = loadDERPMapFromURL(*addr)
	require.ErrorIs(t, err, ErrRegionIDKey)
}

// TestGetDERPMapSkipsFailedSources: a derp.urls server is often run by a
// third party, so one failing source must not cost the regions of the others
// (https://github.com/juanfont/headscale/issues/3142).
func TestGetDERPMapSkipsFailedSources(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Regions": {"1": {"RegionID": 1, "Nodes": [{"Name": "1a", "RegionID": 1}]}}}`))
	}))
	defer good.Close()

	down := httptest.NewServer(http.NotFoundHandler())
	defer down.Close()

	goodURL, err := url.Parse(good.URL)
	require.NoError(t, err)

	downURL, err := url.Parse(down.URL)
	require.NoError(t, err)

	goodPath := filepath.Join(t.TempDir(), "good.yaml")
	require.NoError(t, os.WriteFile(goodPath, []byte(`
regions:
  2:
    regionid: 2
    nodes:
      - name: 2a
        regionid: 2
`), 0o600))

	brokenPath := filepath.Join(t.TempDir(), "broken.yaml")
	require.NoError(t, os.WriteFile(brokenPath, []byte("regions: [\n"), 0o600))

	dm, err := GetDERPMap(types.DERPConfig{
		URLs:  []url.URL{*goodURL, *downURL},
		Paths: []string{goodPath, brokenPath, filepath.Join(t.TempDir(), "missing.yaml")},
	}, "")
	require.ErrorIs(t, err, errDERPMapStatus)
	require.ErrorContains(t, err, down.URL)
	require.ErrorContains(t, err, brokenPath)
	require.ErrorContains(t, err, "missing.yaml")
	require.Contains(t, dm.Regions, tailcfg.DERPRegionID(1))
	require.Contains(t, dm.Regions, tailcfg.DERPRegionID(2))
}

// TestLoadDERPMapFromURLRejectsHTTPError: an error page that happens to be
// JSON must not pass as an empty map, or a refresh drops that URL's regions.
func TestLoadDERPMapFromURLRejectsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"message": "down for maintenance"}`))
	}))
	defer srv.Close()

	addr, err := url.Parse(srv.URL)
	require.NoError(t, err)

	_, err = loadDERPMapFromURL(*addr)
	require.ErrorIs(t, err, errDERPMapStatus)
}
