package mapper

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

var errInjected = errors.New("injected error")

// ============================================================================
// Generators
// ============================================================================

// genBuilderNodeID generates a types.NodeID for builder tests.
func genBuilderNodeID() *rapid.Generator[types.NodeID] {
	return rapid.Custom[types.NodeID](func(t *rapid.T) types.NodeID {
		return types.NodeID(rapid.Uint64Range(1, 1<<53).Draw(t, "nodeID"))
	})
}

// genCapVer generates a tailcfg.CapabilityVersion.
func genCapVer() *rapid.Generator[tailcfg.CapabilityVersion] {
	return rapid.Custom[tailcfg.CapabilityVersion](func(t *rapid.T) tailcfg.CapabilityVersion {
		return tailcfg.CapabilityVersion(rapid.IntRange(0, 200).Draw(t, "capVer"))
	})
}

// genConfig generates a *types.Config with random domain/logtail settings.
func genConfig() *rapid.Generator[*types.Config] {
	return rapid.Custom[*types.Config](func(t *rapid.T) *types.Config {
		baseDomain := rapid.StringMatching(`[a-z]{2,8}\.[a-z]{2,4}`).Draw(t, "baseDomain")
		serverURL := "https://" + rapid.StringMatching(`[a-z]{3,12}\.[a-z]{2,4}`).Draw(t, "serverHost")
		logTailEnabled := rapid.Bool().Draw(t, "logTailEnabled")

		return &types.Config{
			BaseDomain: baseDomain,
			ServerURL:  serverURL,
			LogTail: types.LogTailConfig{
				Enabled: logTailEnabled,
			},
		}
	})
}

// genNodeIDs generates a slice of 0..maxLen types.NodeIDs.
func genNodeIDs(maxLen int) *rapid.Generator[[]types.NodeID] {
	return rapid.Custom[[]types.NodeID](func(t *rapid.T) []types.NodeID {
		n := rapid.IntRange(0, maxLen).Draw(t, "numIDs")

		ids := make([]types.NodeID, n)
		for i := range ids {
			ids[i] = genBuilderNodeID().Draw(t, "id")
		}

		return ids
	})
}

// genPeerChange generates a single *tailcfg.PeerChange.
func genPeerChange() *rapid.Generator[*tailcfg.PeerChange] {
	return rapid.Custom[*tailcfg.PeerChange](func(t *rapid.T) *tailcfg.PeerChange {
		return &tailcfg.PeerChange{
			NodeID:     tailcfg.NodeID(rapid.Uint64Range(1, 1<<53).Draw(t, "changeNodeID")), //nolint:gosec // test with bounded values
			DERPRegion: rapid.IntRange(0, 100).Draw(t, "derpRegion"),
		}
	})
}

// genPeerChanges generates a slice of 0..maxLen PeerChanges.
func genPeerChanges(maxLen int) *rapid.Generator[[]*tailcfg.PeerChange] {
	return rapid.Custom[[]*tailcfg.PeerChange](func(t *rapid.T) []*tailcfg.PeerChange {
		n := rapid.IntRange(0, maxLen).Draw(t, "numChanges")

		changes := make([]*tailcfg.PeerChange, n)
		for i := range changes {
			changes[i] = genPeerChange().Draw(t, "change")
		}

		return changes
	})
}

// newTestMapper creates a mapper with the given config and an empty state,
// suitable for builder methods that don't touch the State.
func newTestMapper(cfg *types.Config) *mapper {
	return &mapper{
		cfg:   cfg,
		state: &state.State{},
	}
}

// ============================================================================
// Which WithX methods to call — a bit-field approach for random combinations
// ============================================================================

// builderAction represents a single state-free WithX operation.
type builderAction int

const (
	actionCapVer builderAction = iota
	actionDomain
	actionCollectServices
	actionDebugConfig
	actionDebugType
	actionCount // sentinel: total number of actions
)

// genActions generates a random subset of builder actions as a sorted,
// deduplicated slice.
func genActions() *rapid.Generator[[]builderAction] {
	return rapid.Custom[[]builderAction](func(t *rapid.T) []builderAction {
		n := rapid.IntRange(0, int(actionCount)).Draw(t, "numActions")

		actions := make([]builderAction, n)
		for i := range actions {
			actions[i] = builderAction(rapid.IntRange(0, int(actionCount)-1).Draw(t, "action"))
		}

		slices.Sort(actions)

		return slices.Compact(actions)
	})
}

// applyActions applies a set of builder actions to a builder.
func applyActions(b *MapResponseBuilder, actions []builderAction, capVer tailcfg.CapabilityVersion) {
	for _, a := range actions {
		switch a {
		case actionCapVer:
			b.WithCapabilityVersion(capVer)
		case actionDomain:
			b.WithDomain()
		case actionCollectServices:
			b.WithCollectServicesDisabled()
		case actionDebugConfig:
			b.WithDebugConfig()
		case actionDebugType:
			b.WithDebugType(fullResponseDebug)
		case actionCount:
			// sentinel value — not a real action
		}
	}
}

// ============================================================================
// Property 1: KeepAlive is always false
// ============================================================================

func TestRapid_Builder_KeepAliveAlwaysFalse(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")
		capVer := genCapVer().Draw(t, "capVer")
		actions := genActions().Draw(t, "actions")

		m := newTestMapper(cfg)
		b := m.NewMapResponseBuilder(nodeID)
		applyActions(b, actions, capVer)

		resp, err := b.Build()
		if err != nil {
			t.Fatalf("unexpected Build error: %v", err)
		}

		if resp.KeepAlive {
			t.Fatal("KeepAlive must be false in every MapResponse from Build()")
		}
	})
}

// ============================================================================
// Property 2: ControlTime is always set and non-zero
// ============================================================================

func TestRapid_Builder_ControlTimeAlwaysSet(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")
		capVer := genCapVer().Draw(t, "capVer")
		actions := genActions().Draw(t, "actions")

		m := newTestMapper(cfg)
		b := m.NewMapResponseBuilder(nodeID)
		applyActions(b, actions, capVer)

		resp, err := b.Build()
		if err != nil {
			t.Fatalf("unexpected Build error: %v", err)
		}

		if resp.ControlTime == nil {
			t.Fatal("ControlTime must not be nil")
		}

		if resp.ControlTime.IsZero() {
			t.Fatal("ControlTime must not be zero")
		}
	})
}

// ============================================================================
// Property 3: Empty builder produces minimal valid response
// ============================================================================

func TestRapid_Builder_EmptyBuilderMinimalResponse(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")

		m := newTestMapper(cfg)

		resp, err := m.NewMapResponseBuilder(nodeID).Build()
		if err != nil {
			t.Fatalf("empty builder should not error: %v", err)
		}

		// No WithX calls => all optional fields should be zero/nil
		if resp.Node != nil {
			t.Fatal("empty builder should have nil Node")
		}

		if resp.DERPMap != nil {
			t.Fatal("empty builder should have nil DERPMap")
		}

		if resp.Peers != nil {
			t.Fatal("empty builder should have nil Peers")
		}

		if resp.PeersChanged != nil {
			t.Fatal("empty builder should have nil PeersChanged")
		}

		if resp.PeersChangedPatch != nil {
			t.Fatal("empty builder should have nil PeersChangedPatch")
		}

		if resp.PeersRemoved != nil {
			t.Fatal("empty builder should have nil PeersRemoved")
		}

		if resp.Domain != "" {
			t.Fatalf("empty builder should have empty Domain, got %q", resp.Domain)
		}

		if resp.Debug != nil {
			t.Fatal("empty builder should have nil Debug")
		}

		if resp.PacketFilters != nil {
			t.Fatal("empty builder should have nil PacketFilters")
		}

		if resp.DNSConfig != nil {
			t.Fatal("empty builder should have nil DNSConfig")
		}

		if resp.SSHPolicy != nil {
			t.Fatal("empty builder should have nil SSHPolicy")
		}

		if resp.UserProfiles != nil {
			t.Fatal("empty builder should have nil UserProfiles")
		}

		// But KeepAlive + ControlTime are still set
		if resp.KeepAlive {
			t.Fatal("KeepAlive must be false")
		}

		if resp.ControlTime == nil || resp.ControlTime.IsZero() {
			t.Fatal("ControlTime must be set even for empty builder")
		}
	})
}

// ============================================================================
// Property 4: Error accumulation — Build() returns error if any error added
// ============================================================================

func TestRapid_Builder_ErrorAccumulation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")
		capVer := genCapVer().Draw(t, "capVer")
		actions := genActions().Draw(t, "actions")

		nErrors := rapid.IntRange(1, 5).Draw(t, "nErrors")

		m := newTestMapper(cfg)
		b := m.NewMapResponseBuilder(nodeID)

		// Inject errors
		for i := range nErrors {
			b.addError(fmt.Errorf("%w: %s", errInjected, rapid.StringMatching(`[a-z]{3,8}`).Draw(t, "errMsg")))

			// Intersperse some WithX calls to show that chaining continues
			if i < len(actions) {
				applyActions(b, actions[i:i+1], capVer)
			}
		}

		// Also apply remaining actions after errors
		applyActions(b, actions, capVer)

		resp, err := b.Build()
		if err == nil {
			t.Fatal("Build() must return error when errors were added")
		}

		if resp != nil {
			t.Fatal("Build() must return nil response when errors exist")
		}

		// Verify error count
		if len(b.errs) != nErrors {
			t.Fatalf("expected %d errors accumulated, got %d", nErrors, len(b.errs))
		}
	})
}

// Property 4b: addError(nil) is a no-op and does not cause Build() to fail.
func TestRapid_Builder_NilErrorIgnored(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")

		nNils := rapid.IntRange(1, 10).Draw(t, "nNils")

		m := newTestMapper(cfg)
		b := m.NewMapResponseBuilder(nodeID)

		for range nNils {
			b.addError(nil)
		}

		resp, err := b.Build()
		if err != nil {
			t.Fatalf("nil errors should be ignored, got: %v", err)
		}

		if resp == nil {
			t.Fatal("response should not be nil when no real errors exist")
		}
	})
}

// ============================================================================
// Property 5: WithPeersRemoved converts NodeIDs correctly
// ============================================================================

func TestRapid_Builder_PeersRemovedConversion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")
		removedIDs := genNodeIDs(10).Draw(t, "removedIDs")

		m := newTestMapper(cfg)
		b := m.NewMapResponseBuilder(nodeID).
			WithPeersRemoved(removedIDs...)

		resp, err := b.Build()
		if err != nil {
			t.Fatalf("unexpected Build error: %v", err)
		}

		// Length must match
		if len(resp.PeersRemoved) != len(removedIDs) {
			t.Fatalf("PeersRemoved length: got %d, want %d",
				len(resp.PeersRemoved), len(removedIDs))
		}

		// Each ID must be correctly converted
		for i, inputID := range removedIDs {
			expected := inputID.NodeID()
			if resp.PeersRemoved[i] != expected {
				t.Fatalf("PeersRemoved[%d]: got %d, want %d",
					i, resp.PeersRemoved[i], expected)
			}
		}
	})
}

// Property 5b: Empty removedIDs → empty (non-nil) PeersRemoved.
func TestRapid_Builder_PeersRemovedEmpty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")

		m := newTestMapper(cfg)
		b := m.NewMapResponseBuilder(nodeID).
			WithPeersRemoved() // no args

		resp, err := b.Build()
		if err != nil {
			t.Fatalf("unexpected Build error: %v", err)
		}

		// Passing zero variadic args produces a non-nil empty slice
		// because make([]tailcfg.NodeID, 0, 0) is allocated.
		if resp.PeersRemoved == nil {
			t.Fatal("PeersRemoved should be non-nil (allocated empty slice)")
		}

		if len(resp.PeersRemoved) != 0 {
			t.Fatalf("PeersRemoved should be empty, got %d elements", len(resp.PeersRemoved))
		}
	})
}

// ============================================================================
// Property 6: WithPeersRemoved twice overwrites (doesn't append)
// ============================================================================

func TestRapid_Builder_PeersRemovedOverwrites(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")
		firstIDs := genNodeIDs(5).Draw(t, "firstIDs")
		secondIDs := genNodeIDs(5).Draw(t, "secondIDs")

		m := newTestMapper(cfg)
		b := m.NewMapResponseBuilder(nodeID).
			WithPeersRemoved(firstIDs...).
			WithPeersRemoved(secondIDs...)

		resp, err := b.Build()
		if err != nil {
			t.Fatalf("unexpected Build error: %v", err)
		}

		// Second call must completely replace the first
		if len(resp.PeersRemoved) != len(secondIDs) {
			t.Fatalf("PeersRemoved should have %d entries (second call), got %d",
				len(secondIDs), len(resp.PeersRemoved))
		}

		for i, id := range secondIDs {
			expected := id.NodeID()
			if resp.PeersRemoved[i] != expected {
				t.Fatalf("PeersRemoved[%d]: got %d, want %d (from second call)",
					i, resp.PeersRemoved[i], expected)
			}
		}

		// Verify none of the first-call IDs leaked in (unless they happen
		// to also be in the second set)
		secondSet := make(map[tailcfg.NodeID]bool, len(secondIDs))
		for _, id := range secondIDs {
			secondSet[id.NodeID()] = true
		}

		for _, id := range resp.PeersRemoved {
			if !secondSet[id] {
				t.Fatalf("PeersRemoved contains %d which is not in the second call set", id)
			}
		}
	})
}

// ============================================================================
// Property 7: WithPeerChangedPatch sets patches directly (passthrough)
// ============================================================================

func TestRapid_Builder_PeerChangedPatchPassthrough(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")
		changes := genPeerChanges(8).Draw(t, "changes")

		m := newTestMapper(cfg)
		b := m.NewMapResponseBuilder(nodeID).
			WithPeerChangedPatch(changes)

		resp, err := b.Build()
		if err != nil {
			t.Fatalf("unexpected Build error: %v", err)
		}

		// Must be the exact same slice (pointer identity for passthrough)
		if len(resp.PeersChangedPatch) != len(changes) {
			t.Fatalf("PeersChangedPatch length: got %d, want %d",
				len(resp.PeersChangedPatch), len(changes))
		}

		for i := range changes {
			if resp.PeersChangedPatch[i] != changes[i] {
				t.Fatalf("PeersChangedPatch[%d]: pointer mismatch (not passthrough)", i)
			}
		}
	})
}

// Property 7b: nil input → nil output.
func TestRapid_Builder_PeerChangedPatchNil(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")

		m := newTestMapper(cfg)

		resp, err := m.NewMapResponseBuilder(nodeID).
			WithPeerChangedPatch(nil).
			Build()
		if err != nil {
			t.Fatalf("unexpected Build error: %v", err)
		}

		if resp.PeersChangedPatch != nil {
			t.Fatal("WithPeerChangedPatch(nil) should produce nil PeersChangedPatch")
		}
	})
}

// ============================================================================
// Property 8: Build is deterministic — same inputs produce same output
// ============================================================================

func TestRapid_Builder_Deterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")
		capVer := genCapVer().Draw(t, "capVer")
		removedIDs := genNodeIDs(5).Draw(t, "removedIDs")
		changes := genPeerChanges(5).Draw(t, "changes")

		build := func() *tailcfg.MapResponse {
			m := newTestMapper(cfg)

			resp, err := m.NewMapResponseBuilder(nodeID).
				WithCapabilityVersion(capVer).
				WithDomain().
				WithCollectServicesDisabled().
				WithDebugConfig().
				WithPeersRemoved(removedIDs...).
				WithPeerChangedPatch(changes).
				Build()
			if err != nil {
				t.Fatalf("unexpected Build error: %v", err)
			}

			return resp
		}

		r1 := build()
		r2 := build()

		// KeepAlive
		if r1.KeepAlive != r2.KeepAlive {
			t.Fatal("KeepAlive non-deterministic")
		}

		// Domain
		if r1.Domain != r2.Domain {
			t.Fatalf("Domain non-deterministic: %q vs %q", r1.Domain, r2.Domain)
		}

		// CollectServices
		v1, s1 := r1.CollectServices.Get()

		v2, s2 := r2.CollectServices.Get()
		if v1 != v2 || s1 != s2 {
			t.Fatal("CollectServices non-deterministic")
		}

		// Debug
		if (r1.Debug == nil) != (r2.Debug == nil) {
			t.Fatal("Debug presence non-deterministic")
		}

		if r1.Debug != nil && r1.Debug.DisableLogTail != r2.Debug.DisableLogTail {
			t.Fatal("Debug.DisableLogTail non-deterministic")
		}

		// PeersRemoved
		if !slices.Equal(r1.PeersRemoved, r2.PeersRemoved) {
			t.Fatal("PeersRemoved non-deterministic")
		}

		// PeersChangedPatch length + NodeIDs
		if len(r1.PeersChangedPatch) != len(r2.PeersChangedPatch) {
			t.Fatal("PeersChangedPatch length non-deterministic")
		}

		for i := range r1.PeersChangedPatch {
			if r1.PeersChangedPatch[i].NodeID != r2.PeersChangedPatch[i].NodeID {
				t.Fatalf("PeersChangedPatch[%d].NodeID non-deterministic", i)
			}

			if r1.PeersChangedPatch[i].DERPRegion != r2.PeersChangedPatch[i].DERPRegion {
				t.Fatalf("PeersChangedPatch[%d].DERPRegion non-deterministic", i)
			}
		}
	})
}

// ============================================================================
// Cross-cutting: WithDomain sets Domain to cfg.Domain()
// ============================================================================

func TestRapid_Builder_WithDomainMatchesConfig(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")

		m := newTestMapper(cfg)

		resp, err := m.NewMapResponseBuilder(nodeID).
			WithDomain().
			Build()
		if err != nil {
			t.Fatalf("unexpected Build error: %v", err)
		}

		expected := cfg.Domain()
		if resp.Domain != expected {
			t.Fatalf("Domain: got %q, want %q (from cfg.Domain())", resp.Domain, expected)
		}
	})
}

// ============================================================================
// Cross-cutting: WithCollectServicesDisabled always sets false
// ============================================================================

func TestRapid_Builder_CollectServicesAlwaysFalse(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")

		m := newTestMapper(cfg)

		resp, err := m.NewMapResponseBuilder(nodeID).
			WithCollectServicesDisabled().
			Build()
		if err != nil {
			t.Fatalf("unexpected Build error: %v", err)
		}

		val, isSet := resp.CollectServices.Get()
		if !isSet {
			t.Fatal("CollectServices should be explicitly set after WithCollectServicesDisabled")
		}

		if val {
			t.Fatal("CollectServices must be false after WithCollectServicesDisabled")
		}
	})
}

// ============================================================================
// Cross-cutting: WithDebugConfig DisableLogTail is negation of cfg.LogTail.Enabled
// ============================================================================

func TestRapid_Builder_DebugConfigLogTailInversion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")

		m := newTestMapper(cfg)

		resp, err := m.NewMapResponseBuilder(nodeID).
			WithDebugConfig().
			Build()
		if err != nil {
			t.Fatalf("unexpected Build error: %v", err)
		}

		if resp.Debug == nil {
			t.Fatal("Debug should be set after WithDebugConfig")
		}

		// DisableLogTail == !cfg.LogTail.Enabled
		expected := !cfg.LogTail.Enabled
		if resp.Debug.DisableLogTail != expected {
			t.Fatalf("DisableLogTail: got %v, want %v (negation of LogTail.Enabled=%v)",
				resp.Debug.DisableLogTail, expected, cfg.LogTail.Enabled)
		}
	})
}

// ============================================================================
// Cross-cutting: Builder fluency — every WithX returns the same builder
// ============================================================================

func TestRapid_Builder_FluentChainReturnsSamePointer(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")
		capVer := genCapVer().Draw(t, "capVer")

		m := newTestMapper(cfg)
		b := m.NewMapResponseBuilder(nodeID)

		// Each WithX must return the same *MapResponseBuilder
		b2 := b.WithCapabilityVersion(capVer)
		if b2 != b {
			t.Fatal("WithCapabilityVersion returned different pointer")
		}

		b3 := b.WithDomain()
		if b3 != b {
			t.Fatal("WithDomain returned different pointer")
		}

		b4 := b.WithCollectServicesDisabled()
		if b4 != b {
			t.Fatal("WithCollectServicesDisabled returned different pointer")
		}

		b5 := b.WithDebugConfig()
		if b5 != b {
			t.Fatal("WithDebugConfig returned different pointer")
		}

		b6 := b.WithDebugType(fullResponseDebug)
		if b6 != b {
			t.Fatal("WithDebugType returned different pointer")
		}

		ids := genNodeIDs(3).Draw(t, "ids")

		b7 := b.WithPeersRemoved(ids...)
		if b7 != b {
			t.Fatal("WithPeersRemoved returned different pointer")
		}

		changes := genPeerChanges(3).Draw(t, "changes")

		b8 := b.WithPeerChangedPatch(changes)
		if b8 != b {
			t.Fatal("WithPeerChangedPatch returned different pointer")
		}
	})
}

// ============================================================================
// Cross-cutting: Order independence of WithX calls (for state-free methods)
// ============================================================================

func TestRapid_Builder_OrderIndependence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := genConfig().Draw(t, "cfg")
		nodeID := genBuilderNodeID().Draw(t, "nodeID")
		capVer := genCapVer().Draw(t, "capVer")
		removedIDs := genNodeIDs(5).Draw(t, "removedIDs")

		// Build with one order
		m1 := newTestMapper(cfg)

		r1, err := m1.NewMapResponseBuilder(nodeID).
			WithCapabilityVersion(capVer).
			WithDomain().
			WithCollectServicesDisabled().
			WithDebugConfig().
			WithPeersRemoved(removedIDs...).
			Build()
		if err != nil {
			t.Fatalf("Build (order 1) error: %v", err)
		}

		// Build with reversed order
		m2 := newTestMapper(cfg)

		r2, err := m2.NewMapResponseBuilder(nodeID).
			WithPeersRemoved(removedIDs...).
			WithDebugConfig().
			WithCollectServicesDisabled().
			WithDomain().
			WithCapabilityVersion(capVer).
			Build()
		if err != nil {
			t.Fatalf("Build (order 2) error: %v", err)
		}

		// Results must be equivalent
		if r1.Domain != r2.Domain {
			t.Fatalf("Domain differs: %q vs %q", r1.Domain, r2.Domain)
		}

		v1, s1 := r1.CollectServices.Get()

		v2, s2 := r2.CollectServices.Get()
		if v1 != v2 || s1 != s2 {
			t.Fatal("CollectServices differs")
		}

		if (r1.Debug == nil) != (r2.Debug == nil) {
			t.Fatal("Debug presence differs")
		}

		if r1.Debug != nil && r1.Debug.DisableLogTail != r2.Debug.DisableLogTail {
			t.Fatal("Debug.DisableLogTail differs")
		}

		if !slices.Equal(r1.PeersRemoved, r2.PeersRemoved) {
			t.Fatal("PeersRemoved differs")
		}
	})
}
