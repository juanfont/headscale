package hscontrol

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
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
	ctx    context.Context
	capVer tailcfg.CapabilityVersion

	cancelChMu deadlock.Mutex

	ch           chan *tailcfg.MapResponse
	cancelCh     chan struct{}
	cancelChOpen bool

	keepAlive       time.Duration
	keepAliveTicker *time.Ticker

	node *types.Node
	w    http.ResponseWriter

	warnf  func(string, ...any)
	infof  func(string, ...any)
	tracef func(string, ...any)
	errf   func(error, string, ...any)
}

func (h *Headscale) newMapSession(
	ctx context.Context,
	req tailcfg.MapRequest,
	w http.ResponseWriter,
	node *types.Node,
) *mapSession {
	warnf, infof, tracef, errf := logPollFunc(req, node)

	ka := keepAliveInterval + (time.Duration(rand.IntN(9000)) * time.Millisecond)

	return &mapSession{
		h:      h,
		ctx:    ctx,
		req:    req,
		w:      w,
		node:   node,
		capVer: req.Version,

		ch:           make(chan *tailcfg.MapResponse, h.cfg.Tuning.NodeMapSessionBufferedChanSize),
		cancelCh:     make(chan struct{}),
		cancelChOpen: true,

		keepAlive:       ka,
		keepAliveTicker: nil,

		// Loggers
		warnf:  warnf,
		infof:  infof,
		tracef: tracef,
		errf:   errf,
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

func (m *mapSession) beforeServeLongPoll() {
	if m.node.IsEphemeral() {
		m.h.ephemeralGC.Cancel(m.node.ID)
	}
}

// afterServeLongPoll is called when a long-polling session ends and the node
// is disconnected.
func (m *mapSession) afterServeLongPoll() {
	if m.node.IsEphemeral() {
		m.h.ephemeralGC.Schedule(m.node.ID, m.h.cfg.EphemeralNodeInactivityTimeout)
	}
}

// serve handles non-streaming requests.
func (m *mapSession) serve() {
	// This is the mechanism where the node gives us information about its
	// current configuration.
	//
	// Process the MapRequest to update node state (endpoints, hostinfo, etc.)
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
	m.beforeServeLongPoll()

	log.Trace().Caller().Uint64("node.id", m.node.ID.Uint64()).Str("node.name", m.node.Hostname).Msg("Long poll session started because client connected")

	// Clean up the session when the client disconnects
	defer func() {
		m.cancelChMu.Lock()
		m.cancelChOpen = false
		close(m.cancelCh)
		m.cancelChMu.Unlock()

		_ = m.h.mapBatcher.RemoveNode(m.node.ID, m.ch)

		// When a node disconnects, it might rapidly reconnect (e.g. mobile clients, network weather).
		// Instead of immediately marking the node as offline, we wait a few seconds to see if it reconnects.
		// If it does reconnect, the existing mapSession will be replaced and the node remains online.
		// If it doesn't reconnect within the timeout, we mark it as offline.
		//
		// This avoids flapping nodes in the UI and unnecessary churn in the network.
		// This is not my favourite solution, but it kind of works in our eventually consistent world.
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		disconnected := true
		// Wait up to 10 seconds for the node to reconnect.
		// 10 seconds was arbitrary chosen as a reasonable time to reconnect.
		for range 10 {
			if m.h.mapBatcher.IsConnected(m.node.ID) {
				disconnected = false
				break
			}
			<-ticker.C
		}

		if disconnected {
			disconnectChanges, err := m.h.state.Disconnect(m.node.ID)
			if err != nil {
				m.errf(err, "Failed to disconnect node %s", m.node.Hostname)
			}

			m.h.Change(disconnectChanges...)
			m.afterServeLongPoll()
			m.infof("node has disconnected, mapSession: %p, chan: %p", m, m.ch)
		}
	}()

	// Set up the client stream
	m.h.clientStreamsOpen.Add(1)
	defer m.h.clientStreamsOpen.Done()

	ctx, cancel := context.WithCancel(context.WithValue(m.ctx, nodeNameContextKey, m.node.Hostname))
	defer cancel()

	m.keepAliveTicker = time.NewTicker(m.keepAlive)

	// Process the initial MapRequest to update node state (endpoints, hostinfo, etc.)
	// CRITICAL: This must be done BEFORE calling Connect() to ensure routes are properly
	// synchronized. When nodes reconnect, they send their hostinfo with announced routes
	// in the MapRequest. We need this data in NodeStore before Connect() sets up the
	// primary routes, otherwise SubnetRoutes() returns empty and the node is removed
	// from AvailableRoutes.
	mapReqChange, err := m.h.state.UpdateNodeFromMapRequest(m.node.ID, m.req)
	if err != nil {
		m.errf(err, "failed to update node from initial MapRequest")
		return
	}

	// Connect the node after its state has been updated.
	// We send two separate change notifications because these are distinct operations:
	// 1. UpdateNodeFromMapRequest: processes the client's reported state (routes, endpoints, hostinfo)
	// 2. Connect: marks the node online and recalculates primary routes based on the updated state
	// While this results in two notifications, it ensures route data is synchronized before
	// primary route selection occurs, which is critical for proper HA subnet router failover.
	connectChanges := m.h.state.Connect(m.node.ID)

	m.infof("node has connected, mapSession: %p, chan: %p", m, m.ch)

	// TODO(kradalby): Redo the comments here
	// Add node to batcher so it can receive updates,
	// adding this before connecting it to the state ensure that
	// it does not miss any updates that might be sent in the split
	// time between the node connecting and the batcher being ready.
	if err := m.h.mapBatcher.AddNode(m.node.ID, m.ch, m.capVer); err != nil {
		m.errf(err, "failed to add node to batcher")
		log.Error().Uint64("node.id", m.node.ID.Uint64()).Str("node.name", m.node.Hostname).Err(err).Msg("AddNode failed in poll session")
		return
	}
	log.Debug().Caller().Uint64("node.id", m.node.ID.Uint64()).Str("node.name", m.node.Hostname).Msg("AddNode succeeded in poll session because node added to batcher")

	m.h.Change(mapReqChange)
	m.h.Change(connectChanges...)

	// Loop through updates and continuously send them to the
	// client.
	for {
		// consume channels with update, keep alives or "batch" blocking signals
		select {
		case <-m.cancelCh:
			m.tracef("poll cancelled received")
			mapResponseEnded.WithLabelValues("cancelled").Inc()
			return

		case <-ctx.Done():
			m.tracef("poll context done chan:%p", m.ch)
			mapResponseEnded.WithLabelValues("done").Inc()
			return

		// Consume updates sent to node
		case update, ok := <-m.ch:
			m.tracef("received update from channel, ok: %t", ok)
			if !ok {
				m.tracef("update channel closed, streaming session is likely being replaced")
				return
			}

			if err := m.writeMap(update); err != nil {
				m.errf(err, "cannot write update to client")
				return
			}

			m.tracef("update sent")
			m.resetKeepAlive()

		case <-m.keepAliveTicker.C:
			if err := m.writeMap(&keepAlive); err != nil {
				m.errf(err, "cannot write keep alive")
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
// It also handles flushing the response if the ResponseWriter
// implements http.Flusher.
func (m *mapSession) writeMap(msg *tailcfg.MapResponse) error {
	jsonBody, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling map response: %w", err)
	}

	if m.req.Compress == util.ZstdCompression {
		jsonBody = zstdframe.AppendEncode(nil, jsonBody, zstdframe.FastestCompression)
	}

	data := make([]byte, reservedResponseHeaderSize)
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
			m.errf(nil, "ResponseWriter does not implement http.Flusher, cannot flush")
		}
	}

	log.Trace().
		Caller().
		Str("node.name", m.node.Hostname).
		Uint64("node.id", m.node.ID.Uint64()).
		Str("chan", fmt.Sprintf("%p", m.ch)).
		TimeDiff("timeSpent", time.Now(), startWrite).
		Str("machine.key", m.node.MachineKey.String()).
		Bool("keepalive", msg.KeepAlive).
		Msgf("finished writing mapresp to node chan(%p)", m.ch)

	return nil
}

var keepAlive = tailcfg.MapResponse{
	KeepAlive: true,
}

func logTracePeerChange(hostname string, hostinfoChange bool, peerChange *tailcfg.PeerChange) {
	trace := log.Trace().Caller().Uint64("node.id", uint64(peerChange.NodeID)).Str("hostname", hostname)

	if peerChange.Key != nil {
		trace = trace.Str("node.key", peerChange.Key.ShortString())
	}

	if peerChange.DiscoKey != nil {
		trace = trace.Str("disco.key", peerChange.DiscoKey.ShortString())
	}

	if peerChange.Online != nil {
		trace = trace.Bool("online", *peerChange.Online)
	}

	if peerChange.Endpoints != nil {
		eps := make([]string, len(peerChange.Endpoints))
		for idx, ep := range peerChange.Endpoints {
			eps[idx] = ep.String()
		}

		trace = trace.Strs("endpoints", eps)
	}

	if hostinfoChange {
		trace = trace.Bool("hostinfo_changed", hostinfoChange)
	}

	if peerChange.DERPRegion != 0 {
		trace = trace.Int("derp_region", peerChange.DERPRegion)
	}

	trace.Time("last_seen", *peerChange.LastSeen).Msg("PeerChange received")
}

func logPollFunc(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
) (func(string, ...any), func(string, ...any), func(string, ...any), func(error, string, ...any)) {
	return func(msg string, a ...any) {
			log.Warn().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node.name", node.Hostname).
				Msgf(msg, a...)
		},
		func(msg string, a ...any) {
			log.Info().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node.name", node.Hostname).
				Msgf(msg, a...)
		},
		func(msg string, a ...any) {
			log.Trace().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node.name", node.Hostname).
				Msgf(msg, a...)
		},
		func(err error, msg string, a ...any) {
			log.Error().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node.name", node.Hostname).
				Err(err).
				Msgf(msg, a...)
		}
}
