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
	"github.com/juanfont/headscale/hscontrol/types/change"
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
		c, err := m.h.state.UpdateNodeFromMapRequest(m.node, m.req)
		if err != nil {
			httpError(m.w, err)
			return
		}

		m.h.Change(c)

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

	// Clean up the session when the client disconnects
	defer func() {
		m.cancelChMu.Lock()
		m.cancelChOpen = false
		close(m.cancelCh)
		m.cancelChMu.Unlock()

		// TODO(kradalby): This can likely be made more effective, but likely most
		// nodes has access to the same routes, so it might not be a big deal.
		disconnectChange, err := m.h.state.Disconnect(m.node)
		if err != nil {
			m.errf(err, "Failed to disconnect node %s", m.node.Hostname)
		}
		m.h.Change(disconnectChange)

		m.h.mapBatcher.RemoveNode(m.node.ID, m.ch, m.node.IsSubnetRouter())

		m.afterServeLongPoll()
		m.infof("node has disconnected, mapSession: %p, chan: %p", m, m.ch)
	}()

	// Set up the client stream
	m.h.pollNetMapStreamWG.Add(1)
	defer m.h.pollNetMapStreamWG.Done()

	ctx, cancel := context.WithCancel(context.WithValue(m.ctx, nodeNameContextKey, m.node.Hostname))
	defer cancel()

	m.keepAliveTicker = time.NewTicker(m.keepAlive)

	// Add node to batcher BEFORE sending Connect change to prevent race condition
	// where the change is sent before the node is in the batcher's node map
	if err := m.h.mapBatcher.AddNode(m.node.ID, m.ch, m.node.IsSubnetRouter(), m.capVer); err != nil {
		m.errf(err, "failed to add node to batcher")
		// Send empty response to client to fail fast for invalid/non-existent nodes
		select {
		case m.ch <- &tailcfg.MapResponse{}:
		default:
			// Channel might be closed
		}
		return
	}

	// Now send the Connect change - the batcher handles NodeCameOnline internally
	// but we still need to update routes and other state-level changes
	connectChange := m.h.state.Connect(m.node)
	if !connectChange.Empty() && connectChange.Change != change.NodeCameOnline {
		m.h.Change(connectChange)
	}

	m.infof("node has connected, mapSession: %p, chan: %p", m, m.ch)

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
			m.tracef("poll context done")
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

	log.Trace().Str("node", m.node.Hostname).TimeDiff("timeSpent", time.Now(), startWrite).Str("mkey", m.node.MachineKey.String()).Msg("finished writing mapresp to node")

	return nil
}

var keepAlive = tailcfg.MapResponse{
	KeepAlive: true,
}

func logTracePeerChange(hostname string, hostinfoChange bool, peerChange *tailcfg.PeerChange) {
	trace := log.Trace().Uint64("node.id", uint64(peerChange.NodeID)).Str("hostname", hostname)

	if peerChange.Key != nil {
		trace = trace.Str("node_key", peerChange.Key.ShortString())
	}

	if peerChange.DiscoKey != nil {
		trace = trace.Str("disco_key", peerChange.DiscoKey.ShortString())
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
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(msg string, a ...any) {
			log.Info().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(msg string, a ...any) {
			log.Trace().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(err error, msg string, a ...any) {
			log.Error().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node", node.Hostname).
				Err(err).
				Msgf(msg, a...)
		}
}
