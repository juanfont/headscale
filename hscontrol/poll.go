package hscontrol

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"
)

const (
	keepAliveInterval = 50 * time.Second
)

type contextKey string

const nodeNameContextKey = contextKey("nodeName")

type mapSession struct {
	h      *Headscale
	req    tailcfg.MapRequest
	ctx    context.Context //nolint:containedctx
	capVer tailcfg.CapabilityVersion

	ch             chan *tailcfg.MapResponse
	cancelCh       chan struct{}
	cancelChClosed atomic.Bool

	keepAlive       time.Duration
	keepAliveTicker *time.Ticker

	node *types.Node
	w    http.ResponseWriter

	log zerolog.Logger
}

func (h *Headscale) newMapSession(
	ctx context.Context,
	req tailcfg.MapRequest,
	w http.ResponseWriter,
	node *types.Node,
) *mapSession {
	ka := keepAliveInterval + (time.Duration(rand.IntN(9000)) * time.Millisecond) //nolint:gosec // weak random is fine for jitter

	return &mapSession{
		h:      h,
		ctx:    ctx,
		req:    req,
		w:      w,
		node:   node,
		capVer: req.Version,

		ch:       make(chan *tailcfg.MapResponse, h.cfg.Tuning.NodeMapSessionBufferedChanSize),
		cancelCh: make(chan struct{}),

		keepAlive:       ka,
		keepAliveTicker: nil,

		log: log.With().
			Str(zf.Component, "poll").
			EmbedObject(node).
			Bool(zf.OmitPeers, req.OmitPeers).
			Bool(zf.Stream, req.Stream).
			Logger(),
	}
}

func (m *mapSession) isStreaming() bool {
	return m.req.Stream
}

func (m *mapSession) isEndpointUpdate() bool {
	return !m.req.Stream && m.req.OmitPeers
}

func (m *mapSession) resetKeepAlive() {
	m.keepAliveTicker.Reset(m.keepAlive)
}

func (m *mapSession) stopFromBatcher() {
	if m.cancelChClosed.CompareAndSwap(false, true) {
		close(m.cancelCh)
	}
}

// afterServeLongPoll is called when a long-polling session ends and the node
// is disconnected.
func (m *mapSession) afterServeLongPoll() {
	if m.node.IsEphemeral() {
		m.h.ephemeralGC.Schedule(m.node.ID, m.h.cfg.Node.Ephemeral.InactivityTimeout)
	}
}

// serve handles non-streaming requests.
func (m *mapSession) serve() {
	// This is the mechanism where the node gives us information about its
	// current configuration.
	//
	// Process the [tailcfg.MapRequest] to update node state (endpoints, hostinfo, etc.)
	c, err := m.h.state.UpdateNodeFromMapRequest(m.node.ID, m.req)
	if err != nil {
		httpError(m.w, err)
		return
	}

	m.h.Change(c)

	// If OmitPeers is true and Stream is false
	// then the server will let clients update their endpoints without
	// breaking existing long-polling (Stream == true) connections.
	// In this case, the server can omit the entire response; the client
	// only checks the HTTP response status code.
	//
	// This is what Tailscale calls a Lite update, the client ignores
	// the response and just wants a 200.
	// !req.stream && req.OmitPeers
	if m.isEndpointUpdate() {
		m.w.WriteHeader(http.StatusOK)
		mapResponseEndpointUpdates.WithLabelValues("ok").Inc()
	}
}

// serveLongPoll ensures the node gets the appropriate updates from either
// polling or immediate responses.
//
//nolint:gocyclo
func (m *mapSession) serveLongPoll() {
	m.log.Trace().Caller().Msg("long poll session started")

	// connectGen is set by [state.State.Connect] below and captured by the deferred cleanup closure.
	// Each Connect acquires one live session in state; the cleanup must release
	// it with exactly one [state.State.Disconnect] call, in every exit path, or
	// the node's session count leaks and it stays online forever.
	var connectGen uint64

	// Clean up the session when the client disconnects
	defer func() {
		m.stopFromBatcher()

		stillConnected := m.h.mapBatcher.RemoveNode(m.node.ID, m.ch)

		// This session never reached [state.State.Connect]; there is no
		// session to release.
		if connectGen == 0 {
			return
		}

		// When a node disconnects, it might rapidly reconnect (e.g. mobile clients, network weather).
		// Instead of immediately marking the node as offline, we wait a few seconds to see if it reconnects.
		// If it reconnects during the wait, the new session's Connect raises the
		// session count, so the release below keeps the node online.
		//
		// This avoids flapping nodes in the UI and unnecessary churn in the network.
		// This is not my favourite solution, but it kind of works in our eventually consistent world.
		//
		// When another session already replaced this one (stillConnected), skip
		// the wait — but never the release itself. A cancelled map request whose
		// handler ran late is exactly such a session: if it kept its session
		// acquired on this path, the surviving session's release could never
		// take the node offline (the relogin flake).
		if !stillConnected {
			// Wait up to 10 seconds for the node to reconnect.
			// 10 seconds was arbitrary chosen as a reasonable time to reconnect.
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for range 10 {
				if m.h.mapBatcher.IsConnected(m.node.ID) {
					break
				}

				<-ticker.C
			}
		}

		// Release this session. The node goes offline exactly when the last
		// live session is released, so releases from replaced or stale
		// sessions are harmless regardless of the order they run in.
		disconnectChanges, err := m.h.state.Disconnect(m.node.ID, connectGen)
		if err != nil {
			m.log.Error().Caller().Err(err).Msg("failed to disconnect node")
		}

		if len(disconnectChanges) == 0 {
			return
		}

		m.h.Change(disconnectChanges...)
		m.afterServeLongPoll()
		m.log.Info().Caller().Str(zf.Chan, fmt.Sprintf("%p", m.ch)).Msg("node has disconnected")
	}()

	// Set up the client stream
	m.h.clientStreamsOpen.Add(1)
	defer m.h.clientStreamsOpen.Done()

	ctx, cancel := context.WithCancel(context.WithValue(m.ctx, nodeNameContextKey, m.node.Hostname))
	defer cancel()

	m.keepAliveTicker = time.NewTicker(m.keepAlive)

	// Process the initial [tailcfg.MapRequest] to update node state (endpoints, hostinfo, etc.)
	// This must be done BEFORE calling [state.State.Connect] to ensure routes are properly synchronized.
	// When nodes reconnect, they send their hostinfo with announced routes in the [tailcfg.MapRequest].
	// We need this data in [state.NodeStore] before [state.State.Connect] sets up the primary routes, because
	// [types.NodeView.SubnetRoutes] calculates the intersection of announced and approved routes. If we
	// call [state.State.Connect] first, [types.NodeView.SubnetRoutes] returns empty (no announced routes yet), causing
	// the node to be incorrectly removed from AvailableRoutes.
	mapReqChange, err := m.h.state.UpdateNodeFromMapRequest(m.node.ID, m.req)
	if err != nil {
		m.log.Error().Caller().Err(err).Msg("failed to update node from initial MapRequest")
		// Write an explicit error rather than returning silently: a bare
		// return leaves net/http to send an empty 200, which the client
		// reads as "unexpected EOF" and retries forever (issue #3346).
		httpError(m.w, err)

		return
	}

	// Connect the node after its state has been updated.
	// We send two separate change notifications because these are distinct operations:
	// 1. [state.State.UpdateNodeFromMapRequest]: processes the client's reported state (routes, endpoints, hostinfo)
	// 2. [state.State.Connect]: marks the node online and recalculates primary routes based on the updated state
	// While this results in two notifications, it ensures route data is synchronized before
	// primary route selection occurs, which is critical for proper HA subnet router failover.
	var connectChanges []change.Change

	connectChanges, connectGen = m.h.state.Connect(m.node.ID)

	// Cancel ephemeral GC only after Connect succeeds. Cancelling at the start
	// of serveLongPoll left departed nodes without a deletion timer when a
	// reconnect attempt failed before Connect (issue #3382).
	if m.node.IsEphemeral() {
		m.h.ephemeralGC.Cancel(m.node.ID)
	}

	m.log.Info().Caller().Str(zf.Chan, fmt.Sprintf("%p", m.ch)).Msg("node has connected")

	// TODO(kradalby): Redo the comments here
	// Add node to batcher so it can receive updates,
	// adding this before connecting it to the state ensure that
	// it does not miss any updates that might be sent in the split
	// time between the node connecting and the batcher being ready.
	if err := m.h.mapBatcher.AddNode(m.node.ID, m.ch, m.capVer, m.stopFromBatcher); err != nil { //nolint:noinlineerr
		m.log.Error().Caller().Err(err).Msg("failed to add node to batcher")
		// Write an explicit error rather than returning silently: a bare
		// return leaves net/http to send an empty 200, which the client
		// reads as "unexpected EOF" and retries forever (issue #3346).
		httpError(m.w, err)

		return
	}

	m.log.Debug().Caller().Msg("node added to batcher")

	m.h.Change(mapReqChange)
	m.h.Change(connectChanges...)

	// Loop through updates and continuously send them to the
	// client.
	for {
		// consume channels with update, keep alives or "batch" blocking signals
		select {
		case <-m.cancelCh:
			m.log.Trace().Caller().Msg("poll cancelled received")
			mapResponseEnded.WithLabelValues("cancelled").Inc()

			return

		case <-ctx.Done():
			m.log.Trace().Caller().Str(zf.Chan, fmt.Sprintf("%p", m.ch)).Msg("poll context done")
			mapResponseEnded.WithLabelValues("done").Inc()

			return

		// Consume updates sent to node
		case update, ok := <-m.ch:
			m.log.Trace().Caller().Bool(zf.OK, ok).Msg("received update from channel")

			if !ok {
				m.log.Trace().Caller().Msg("update channel closed, streaming session is likely being replaced")
				return
			}

			err := m.writeMap(update)
			if err != nil {
				m.log.Error().Caller().Err(err).Msg("cannot write update to client")
				return
			}

			m.log.Trace().Caller().Msg("update sent")
			m.resetKeepAlive()

		case <-m.keepAliveTicker.C:
			err := m.writeMap(&keepAlive)
			if err != nil {
				m.log.Error().Caller().Err(err).Msg("cannot write keep alive")
				return
			}

			if debugHighCardinalityMetrics {
				mapResponseLastSentSeconds.WithLabelValues("keepalive", m.node.ID.String()).Set(float64(time.Now().Unix()))
			}

			mapResponseSent.WithLabelValues("ok", "keepalive").Inc()
			m.resetKeepAlive()
		}
	}
}

// writeMap writes the map response to the client.
// It handles compression if requested and any headers that need to be set.
// It also handles flushing the response if the [http.ResponseWriter]
// implements [http.Flusher].
func (m *mapSession) writeMap(msg *tailcfg.MapResponse) error {
	jsonBody, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling map response: %w", err)
	}

	if m.req.Compress == util.ZstdCompression {
		jsonBody = zstdframe.AppendEncode(nil, jsonBody, zstdframe.FastestCompression)
	}

	data := make([]byte, reservedResponseHeaderSize, reservedResponseHeaderSize+len(jsonBody))
	//nolint:gosec // G115: JSON response size will not exceed uint32 max
	binary.LittleEndian.PutUint32(data, uint32(len(jsonBody)))
	data = append(data, jsonBody...)

	startWrite := time.Now()

	_, err = m.w.Write(data)
	if err != nil {
		return err
	}

	if m.isStreaming() {
		if f, ok := m.w.(http.Flusher); ok {
			f.Flush()
		} else {
			m.log.Error().Caller().Msg("responseWriter does not implement http.Flusher, cannot flush")
		}
	}

	m.log.Trace().
		Caller().
		Str(zf.Chan, fmt.Sprintf("%p", m.ch)).
		TimeDiff("timeSpent", time.Now(), startWrite).
		Str(zf.MachineKey, m.node.MachineKey.String()).
		Bool("keepalive", msg.KeepAlive).
		Msg("finished writing mapresp to node")

	return nil
}

var keepAlive = tailcfg.MapResponse{
	KeepAlive: true,
}
