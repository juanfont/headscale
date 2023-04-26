package hscontrol

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
)

func Test_applyMapResponseDelta(t *testing.T) {
	type TestParameters struct {
		// Metadata
		name string

		// Setup
		previousNodes Machines
		currentNodes  Machines

		// Assertions
		wantPeers        []*tailcfg.Node
		wantPeersChanges []*tailcfg.Node
		wantPeersRemoved []tailcfg.NodeID
	}

	// Time series for indicating change in deltas
	time0 := time.Now()
	time1 := time0.Add(time.Millisecond)

	tests := []TestParameters{
		{
			name:          "full update",
			previousNodes: nil,
			currentNodes: Machines{
				{ID: 1},
				{ID: 2},
			},
			// Full update sends full list in MapResponse.Peers
			wantPeers: []*tailcfg.Node{
				{ID: tailcfg.NodeID(1)},
				{ID: tailcfg.NodeID(2)},
			},
			wantPeersChanges: nil,
			wantPeersRemoved: nil,
		},
		{
			name: "peer removed",
			previousNodes: Machines{
				{ID: 1, LastSuccessfulUpdate: &time0},
				{ID: 2, LastSuccessfulUpdate: &time0},
			},
			currentNodes: Machines{
				{ID: 2, LastSuccessfulUpdate: &time0},
			},
			wantPeers:        nil,
			wantPeersChanges: nil,
			wantPeersRemoved: []tailcfg.NodeID{
				tailcfg.NodeID(1),
			},
		},
		{
			name: "peer added",
			previousNodes: Machines{
				{ID: 1, LastSuccessfulUpdate: &time0},
			},
			currentNodes: Machines{
				{ID: 1, LastSuccessfulUpdate: &time0},
				{ID: 2, LastSuccessfulUpdate: &time0},
			},
			wantPeers: nil,
			wantPeersChanges: []*tailcfg.Node{
				{ID: tailcfg.NodeID(2)},
			},
			wantPeersRemoved: nil,
		},
		{
			name: "peer updated",
			previousNodes: Machines{
				{ID: 1, LastSuccessfulUpdate: &time0},
				{ID: 2, LastSuccessfulUpdate: &time0},
			},
			currentNodes: Machines{
				{ID: 1, LastSuccessfulUpdate: &time1},
				{ID: 2, LastSuccessfulUpdate: &time0},
			},
			wantPeers: nil,
			wantPeersChanges: []*tailcfg.Node{
				{ID: tailcfg.NodeID(1)},
			},
			wantPeersRemoved: nil,
		},
		{
			name: "no change",
			previousNodes: Machines{
				{ID: 1, LastSuccessfulUpdate: &time0},
				{ID: 2, LastSuccessfulUpdate: &time0},
			},
			currentNodes: Machines{
				{ID: 1, LastSuccessfulUpdate: &time0},
				{ID: 2, LastSuccessfulUpdate: &time0},
			},
			wantPeers:        nil,
			wantPeersChanges: nil,
			wantPeersRemoved: nil,
		},
	}

	// Dummy toNodes function which just converts the ID
	toNodes := func(machines Machines) ([]*tailcfg.Node, error) {
		var nodes []*tailcfg.Node
		for _, machine := range machines {
			nodes = append(nodes, &tailcfg.Node{
				ID: tailcfg.NodeID(machine.ID),
			})
		}

		return nodes, nil
	}

	for _, params := range tests {
		t.Run(params.name, func(t *testing.T) {
			streamState := &mapResponseStreamState{}
			if params.previousNodes != nil {
				streamState.peersByID = machinesByID(params.previousNodes)
			}

			mapResponse, err := applyMapResponseDelta(
				tailcfg.MapResponse{},
				streamState,
				params.currentNodes,
				toNodes,
			)

			// No error
			assert.Nil(t, err)

			// Peers
			assert.Equal(t, mapResponse.Peers, params.wantPeers)
			assert.Equal(t, mapResponse.PeersChanged, params.wantPeersChanges)
			assert.Equal(t, mapResponse.PeersRemoved, params.wantPeersRemoved)

			// streamState updated
			assert.Equal(t, streamState.peersByID, machinesByID(params.currentNodes))
		})
	}
}
