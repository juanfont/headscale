package mapper

import (
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// TestExtraRecordsConcurrentUpdateNoRace exercises the extra-records watcher
// write path (Config.SetExtraRecords) concurrently with per-client DNS config
// builds (generateDNSConfig -> Config.CloneTailcfgDNSConfig). Both must go
// through the shared lock so the run is race-free under -race.
func TestExtraRecordsConcurrentUpdateNoRace(t *testing.T) {
	uid := uint(1)
	cfg := &types.Config{
		TailcfgDNSConfig: &tailcfg.DNSConfig{
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: "initial.example.com", Type: "A", Value: "100.64.0.1"},
			},
		},
	}

	node := (&types.Node{
		Hostname: "race-node",
		UserID:   &uid,
		User:     &types.User{Name: "racer"},
	}).View()

	const iterations = 2000

	var wg sync.WaitGroup

	// Writer: the extra-records update path.
	wg.Go(func() {
		for i := range iterations {
			recs := []tailcfg.DNSRecord{{Name: "a.example.com", Type: "A", Value: "100.64.0.2"}}
			if i%2 == 0 {
				recs = append(recs, tailcfg.DNSRecord{Name: "b.example.com", Type: "A", Value: "100.64.0.3"})
			}

			cfg.SetExtraRecords(recs)
		}
	})

	// Readers: the per-client map build path.
	const readers = 8
	for range readers {
		wg.Go(func() {
			for range iterations {
				if d := generateDNSConfig(cfg, node, nil); d != nil {
					_ = len(d.ExtraRecords)
				}
			}
		})
	}

	wg.Wait()
}
