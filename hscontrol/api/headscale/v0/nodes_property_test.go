package apiv0

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// Bound: key expiry is never disabled, and a connected node has exactly one
// session.
func TestRapidNodeWireTime(t *testing.T) {
	var live, offline, absent, fraction, beforeEpoch int

	rapid.Check(t, func(rt *rapid.T) {
		sec := rapid.Int64Range(-2_000_000_000, 4_000_000_000).Draw(rt, "Unix seconds")
		ns := rapid.OneOf(rapid.SampledFrom([]int{0, 1, 999, 1000, 1001, 999999999}), rapid.IntRange(0, 999999999)).
			Draw(rt, "nanoseconds")
		offset := rapid.SampledFrom([]int{0, -7 * 3600, 5*3600 + 30*60, 45 * 60}).
			Draw(rt, "UTC offset")
		now := time.Unix(sec, int64(ns)).In(time.FixedZone("fixture", offset))

		record := types.Node{ID: 1, CreatedAt: now.Add(-48*time.Hour - time.Nanosecond)}
		if rapid.Bool().Draw(rt, "stored last seen") {
			record.LastSeen = new(now.Add(-time.Hour))
		}

		if rapid.Bool().Draw(rt, "expiry") {
			record.Expiry = new(now.Add(12 * time.Hour))
		}

		seen := record.LastSeen
		if rapid.Bool().Draw(rt, "connected") {
			record.ActiveSessions = 1
			seen = &now
			live++
		} else if seen == nil {
			absent++
		} else {
			offline++
		}

		if ns%1000 != 0 {
			fraction++
		}

		if sec < 0 {
			beforeEpoch++
		}

		raw, err := json.Marshal(nodeFromView(record.View(), nil, now, ""))
		if err != nil {
			fatalf(rt, "%v", err)
		}

		var row map[string]json.RawMessage

		err = json.Unmarshal(raw, &row)
		if err != nil {
			fatalf(rt, "%v", err)
		}

		for _, field := range []struct {
			name  string
			value *time.Time
		}{{"lastSeen", seen}, {"created", &record.CreatedAt}, {"expiry", record.Expiry}} {
			name, value := field.name, field.value
			want := "null"

			if value != nil {
				whole := time.UnixMicro(value.UnixMicro()).UTC()
				want = strconv.Quote(whole.Format(time.RFC3339Nano))
			}

			if got := string(row[name]); got != want {
				fatalf(rt, "%s: raw=%s want=%s", name, got, want)
			}
		}
	})
	t.Logf(
		"model classes connected=%d stored-last-seen=%d absent-last-seen=%d submicrosecond=%d before-epoch=%d",
		live,
		offline,
		absent,
		fraction,
		beforeEpoch,
	)
}

func TestNodeWireTimeResponse(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)
	node := *nodes[0].AsStruct()
	stamp := time.Date(2026, 2, 3, 4, 5, 6, 123456789, time.FixedZone("offset", 19800))
	node.ActiveSessions = 0
	node.LastSeen = &stamp
	b.State.PutNodeInStoreForTest(node)

	rec := api.Get(nodePath(nodes[0]), auth)
	require.Equal(t, http.StatusOK, rec.Code)

	var row map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &row))
	require.Equal(t, `"2026-02-02T22:35:06.123456Z"`, string(row["lastSeen"]))
}
