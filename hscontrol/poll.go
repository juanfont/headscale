package hscontrol

import (
	"cmp"
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	xslices "golang.org/x/exp/slices"
	"gorm.io/gorm"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

const (
	keepAliveInterval = 50 * time.Second
)

type contextKey string

const nodeNameContextKey = contextKey("nodeName")

type sessionManager struct {
	mu   sync.RWMutex
	sess map[types.NodeID]*mapSession
}

type mapSession struct {
	h      *Headscale
	req    tailcfg.MapRequest
	ctx    context.Context
	capVer tailcfg.CapabilityVersion
	mapper *mapper.Mapper

	ch       chan types.StateUpdate
	cancelCh chan struct{}

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
	warnf, tracef, infof, errf := logPollFunc(req, node)

	// Use a buffered channel in case a node is not fully ready
	// to receive a message to make sure we dont block the entire
	// notifier.
	// 12 is arbitrarily chosen.
	chanSize := 3
	if size, ok := envknob.LookupInt("HEADSCALE_TUNING_POLL_QUEUE_SIZE"); ok {
		chanSize = size
	}
	updateChan := make(chan types.StateUpdate, chanSize)

	return &mapSession{
		h:      h,
		ctx:    ctx,
		req:    req,
		w:      w,
		node:   node,
		capVer: req.Version,
		mapper: h.mapper,

		ch:       updateChan,
		cancelCh: make(chan struct{}),

		// Loggers
		warnf:  warnf,
		infof:  infof,
		tracef: tracef,
		errf:   errf,
	}
}

func (m *mapSession) close() {
	m.cancelCh <- struct{}{}
}

func (m *mapSession) isStreaming() bool {
	return m.req.Stream && !m.req.ReadOnly
}

func (m *mapSession) isEndpointUpdate() bool {
	return !m.req.Stream && !m.req.ReadOnly && m.req.OmitPeers
}

func (m *mapSession) isReadOnlyUpdate() bool {
	return !m.req.Stream && m.req.OmitPeers && m.req.ReadOnly
}

func (m *mapSession) flush200() {
	m.w.WriteHeader(http.StatusOK)
	if f, ok := m.w.(http.Flusher); ok {
		f.Flush()
	}
}

// handlePoll ensures the node gets the appropriate updates from either
// polling or immediate responses.
//
//nolint:gocyclo
func (m *mapSession) serve() {
	// Register with the notifier if this is a streaming
	// session
	if m.isStreaming() {
		defer m.h.nodeNotifier.RemoveNode(m.node.MachineKey)

		m.h.nodeNotifier.AddNode(m.node.MachineKey, m.ch)
	}

	// TODO(kradalby): A set todos to harden:
	// - func to tell the stream to die, readonly -> false, !stream && omitpeers -> false, true

	// This is the mechanism where the node gives us information about its
	// current configuration.
	//
	// If OmitPeers is true, Stream is false, and ReadOnly is false,
	// then te server will let clients update their endpoints without
	// breaking existing long-polling (Stream == true) connections.
	// In this case, the server can omit the entire response; the client
	// only checks the HTTP response status code.
	//
	// This is what Tailscale calls a Lite update, the client ignores
	// the response and just wants a 200.
	// !req.stream && !req.ReadOnly && req.OmitPeers
	//
	// TODO(kradalby): remove ReadOnly when we only support capVer 68+
	if m.isEndpointUpdate() {
		m.handleEndpointUpdate()

		return
	}

	// ReadOnly is whether the client just wants to fetch the
	// MapResponse, without updating their Endpoints. The
	// Endpoints field will be ignored and LastSeen will not be
	// updated and peers will not be notified of changes.
	//
	// The intended use is for clients to discover the DERP map at
	// start-up before their first real endpoint update.
	if m.isReadOnlyUpdate() {
		m.handleReadOnlyRequest()

		return
	}

	// From version 68, all streaming requests can be treated as read only.
	if m.capVer < 68 {
		// Error has been handled/written to client in the func
		// return
		err := m.handleSaveNode()
		if err != nil {
			return
		}
	}

	// Set up the client stream
	m.h.pollNetMapStreamWG.Add(1)
	defer m.h.pollNetMapStreamWG.Done()

	m.tracef("Sending initial map")

	mapResp, err := m.mapper.FullMapResponse(m.req, m.node, m.h.ACLPolicy)
	if err != nil {
		m.errf(err, "Failed to create MapResponse")
		http.Error(m.w, "", http.StatusInternalServerError)

		return
	}

	// Send the client an update to make sure we send an initial mapresponse
	_, err = m.w.Write(mapResp)
	if err != nil {
		m.errf(err, "Could not write the map response")

		return
	}

	if flusher, ok := m.w.(http.Flusher); ok {
		flusher.Flush()
	} else {
		return
	}

	// TODO(kradalby): I think it would make more sense to tell people when the node
	// registers than connects, thats more of a "is online" update.
	// ctx := types.NotifyCtx(context.Background(), "poll-connected-node-peers", m.node.Hostname)
	// m.h.nodeNotifier.NotifyWithIgnore(
	// 	ctx,
	// 	types.StateUpdate{
	// 		Type:        types.StatePeerChanged,
	// 		ChangeNodes: []types.NodeID{m.node.ID},
	// 		Message:     "called from handlePoll -> node (re)connected",
	// 	},
	// 	m.node.MachineKey.String())

	if len(m.node.Routes) > 0 {
		go m.pollFailoverRoutes("new node", m.node)
	}

	keepAliveTicker := time.NewTicker(keepAliveInterval + (time.Duration(rand.IntN(9000)) * time.Millisecond))

	ctx, cancel := context.WithCancel(context.WithValue(m.ctx, nodeNameContextKey, m.node.Hostname))
	defer cancel()

	for {
		m.tracef("waiting for update on stream channel")
		select {
		case update := <-m.ch:
			m.tracef("received stream update: %d %s", update.Type, update.Message)
			var data []byte
			var err error

			// Ensure the node object is updated, for example, there
			// might have been a hostinfo update in a sidechannel
			// which contains data needed to generate a map response.
			m.node, err = m.h.db.GetNodeByID(m.node.ID)
			if err != nil {
				m.errf(err, "Could not get machine from db")

				return
			}

			startMapResp := time.Now()
			switch update.Type {
			case types.StateFullUpdate:
				m.tracef("Sending Full MapResponse")
				data, err = m.mapper.FullMapResponse(m.req, m.node, m.h.ACLPolicy)
			case types.StatePeerChanged:
				m.tracef(fmt.Sprintf("Sending Changed MapResponse: %s", update.Message))
				data, err = m.mapper.PeerChangedResponse(m.req, m.node, update.ChangeNodes, m.h.ACLPolicy, update.Message)
			case types.StatePeerChangedPatch:
				m.tracef("Sending PeerChangedPatch MapResponse")
				data, err = m.mapper.PeerChangedPatchResponse(m.req, m.node, update.ChangePatches, m.h.ACLPolicy)
			case types.StatePeerRemoved:
				m.tracef("Sending PeerRemoved MapResponse")
				data, err = m.mapper.PeerRemovedResponse(m.req, m.node, update.Removed)
			case types.StateSelfUpdate:
				if len(update.ChangeNodes) == 1 {
					m.tracef("Sending SelfUpdate MapResponse")
					m.node, err = m.h.db.GetNodeByID(m.node.ID)
					if err != nil {
						m.errf(err, "could not update node from db for selfupdate")

						return
					}
					data, err = m.mapper.ReadOnlyMapResponse(m.req, m.node, m.h.ACLPolicy, types.SelfUpdateIdentifier)
				} else {
					m.warnf("SelfUpdate contained too many nodes, this is likely a bug in the code, please report.")
				}
			case types.StateDERPUpdated:
				m.tracef("Sending DERPUpdate MapResponse")
				data, err = m.mapper.DERPMapResponse(m.req, m.node, update.DERPMap)
			}

			if err != nil {
				m.errf(err, "Could not get the create map update")

				return
			}

			log.Trace().Str("node", m.node.Hostname).TimeDiff("timeSpent", time.Now(), startMapResp).Str("mkey", m.node.MachineKey.String()).Int("type", int(update.Type)).Msg("finished making map response")

			// Only send update if there is change
			if data != nil {
				startWrite := time.Now()
				_, err = m.w.Write(data)
				if err != nil {
					m.errf(err, "Could not write the map response")

					updateRequestsSentToNode.WithLabelValues(m.node.User.Name, m.node.Hostname, "failed").
						Inc()

					return
				}

				if flusher, ok := m.w.(http.Flusher); ok {
					flusher.Flush()
				} else {
					log.Error().Msg("Failed to create http flusher")

					return
				}
				log.Trace().Str("node", m.node.Hostname).TimeDiff("timeSpent", time.Now(), startWrite).Str("mkey", m.node.MachineKey.String()).Int("type", int(update.Type)).Msg("finished writing mapresp to node")

				m.infof("update sent")
			}

		case <-keepAliveTicker.C:
			data, err := m.mapper.KeepAliveResponse(m.req, m.node)
			if err != nil {
				m.errf(err, "Error generating the keep alive msg")

				return
			}
			_, err = m.w.Write(data)
			if err != nil {
				m.errf(err, "Cannot write keep alive message")

				return
			}
			if flusher, ok := m.w.(http.Flusher); ok {
				flusher.Flush()
			} else {
				log.Error().Msg("Failed to create http flusher")

				return
			}

			// This goroutine is not ideal, but we have a potential issue here
			// where it blocks too long and that holds up updates.
			// One alternative is to split these different channels into
			// goroutines, but then you might have a problem without a lock
			// if a keepalive is written at the same time as an update.
			// go m.h.updateNodeOnlineStatus(true, m.node)

		case <-ctx.Done():
			m.tracef("The client has closed the connection")

			go m.h.updateNodeOnlineStatus(false, m.node)

			// Failover the node's routes if any.
			go m.pollFailoverRoutes("node closing connection", m.node)

			// The connection has been closed, so we can stop polling.
			return

		case <-m.cancelCh:
			return
		}

	}
}

func (m *mapSession) pollFailoverRoutes(where string, node *types.Node) {
	update, err := db.Write(m.h.db.DB, func(tx *gorm.DB) (*types.StateUpdate, error) {
		return db.EnsureFailoverRouteIsAvailable(tx, m.h.nodeNotifier.ConnectedMap(), node)
	})
	if err != nil {
		m.errf(err, fmt.Sprintf("failed to ensure failover routes, %s", where))

		return
	}

	if update != nil && !update.Empty() {
		ctx := types.NotifyCtx(context.Background(), fmt.Sprintf("poll-%s-routes-ensurefailover", strings.ReplaceAll(where, " ", "-")), node.Hostname)
		m.h.nodeNotifier.NotifyWithIgnore(ctx, *update, node.MachineKey.String())
	}
}

// updateNodeOnlineStatus records the last seen status of a node and notifies peers
// about change in their online/offline status.
// It takes a StateUpdateType of either StatePeerOnlineChanged or StatePeerOfflineChanged.
func (h *Headscale) updateNodeOnlineStatus(online bool, node *types.Node) {
	now := time.Now()

	node.LastSeen = &now

	ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-onlinestatus", node.Hostname)
	h.nodeNotifier.NotifyWithIgnore(ctx, types.StateUpdate{
		Type: types.StatePeerChangedPatch,
		ChangePatches: []*tailcfg.PeerChange{
			{
				NodeID:   tailcfg.NodeID(node.ID),
				Online:   &online,
				LastSeen: &now,
			},
		},
	}, node.MachineKey.String())

	err := h.db.DB.Transaction(func(tx *gorm.DB) error {
		return db.UpdateLastSeen(tx, node.ID, *node.LastSeen)
	})
	if err != nil {
		log.Error().Err(err).Msg("Cannot update node LastSeen")

		return
	}
}

func closeChanWithLog[C chan []byte | chan struct{} | chan types.StateUpdate](channel C, node, name string) {
	log.Trace().
		Str("handler", "PollNetMap").
		Str("node", node).
		Str("channel", "Done").
		Msg(fmt.Sprintf("Closing %s channel", name))

	close(channel)
}

func (m *mapSession) handleEndpointUpdate() {
	m.tracef("received endpoint update")

	change := m.node.PeerChangeFromMapRequest(m.req)

	online := m.h.nodeNotifier.IsLikelyConnected(m.node.MachineKey)
	change.Online = &online

	m.node.ApplyPeerChange(&change)

	sendUpdate, routesChanged := hostInfoChanged(m.node.Hostinfo, m.req.Hostinfo)
	m.node.Hostinfo = m.req.Hostinfo

	logTracePeerChange(m.node.Hostname, sendUpdate, &change)

	// If there is no changes and nothing to save,
	// return early.
	if peerChangeEmpty(change) && !sendUpdate {
		return
	}

	// Check if the Hostinfo of the node has changed.
	// If it has changed, check if there has been a change to
	// the routable IPs of the host and update update them in
	// the database. Then send a Changed update
	// (containing the whole node object) to peers to inform about
	// the route change.
	// If the hostinfo has changed, but not the routes, just update
	// hostinfo and let the function continue.
	if routesChanged {
		var err error
		_, err = m.h.db.SaveNodeRoutes(m.node)
		if err != nil {
			m.errf(err, "Error processing node routes")
			http.Error(m.w, "", http.StatusInternalServerError)

			return
		}

		if m.h.ACLPolicy != nil {
			// update routes with peer information
			err := m.h.db.EnableAutoApprovedRoutes(m.h.ACLPolicy, m.node)
			if err != nil {
				m.errf(err, "Error running auto approved routes")
			}
		}

		// Send an update to the node itself with to ensure it
		// has an updated packetfilter allowing the new route
		// if it is defined in the ACL.
		ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-self-hostinfochange", m.node.Hostname)
		m.h.nodeNotifier.NotifyByMachineKey(
			ctx,
			types.StateUpdate{
				Type:        types.StateSelfUpdate,
				ChangeNodes: []types.NodeID{m.node.ID},
			},
			m.node.MachineKey)

	}

	if err := m.h.db.DB.Save(m.node).Error; err != nil {
		m.errf(err, "Failed to persist/update node in the database")
		http.Error(m.w, "", http.StatusInternalServerError)

		return
	}

	ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-peers-patch", m.node.Hostname)
	m.h.nodeNotifier.NotifyWithIgnore(
		ctx,
		types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: []types.NodeID{m.node.ID},
			Message:     "called from handlePoll -> update",
		},
		m.node.MachineKey.String())

	m.flush200()

	return
}

// handleSaveNode saves node updates in the maprequest _streaming_
// path and is mostly the same code as in handleEndpointUpdate.
// It is not attempted to be deduplicated since it will go away
// when we stop supporting older than 68 which removes updates
// when the node is streaming.
func (m *mapSession) handleSaveNode() error {
	m.tracef("saving node update from stream session")

	change := m.node.PeerChangeFromMapRequest(m.req)

	// A stream is being set up, the node is Online
	online := true
	change.Online = &online

	m.node.ApplyPeerChange(&change)

	sendUpdate, routesChanged := hostInfoChanged(m.node.Hostinfo, m.req.Hostinfo)
	m.node.Hostinfo = m.req.Hostinfo

	// If there is no changes and nothing to save,
	// return early.
	if peerChangeEmpty(change) || !sendUpdate {
		return nil
	}

	// Check if the Hostinfo of the node has changed.
	// If it has changed, check if there has been a change to
	// the routable IPs of the host and update update them in
	// the database. Then send a Changed update
	// (containing the whole node object) to peers to inform about
	// the route change.
	// If the hostinfo has changed, but not the routes, just update
	// hostinfo and let the function continue.
	if routesChanged {
		var err error
		_, err = m.h.db.SaveNodeRoutes(m.node)
		if err != nil {
			return err
		}

		if m.h.ACLPolicy != nil {
			// update routes with peer information
			err := m.h.db.EnableAutoApprovedRoutes(m.h.ACLPolicy, m.node)
			if err != nil {
				return err
			}
		}
	}

	if err := m.h.db.DB.Save(m.node).Error; err != nil {
		return err
	}

	return nil
}

func (m *mapSession) handleReadOnlyRequest() {
	m.tracef("Client asked for a lite update, responding without peers")

	mapResp, err := m.mapper.ReadOnlyMapResponse(m.req, m.node, m.h.ACLPolicy)
	if err != nil {
		m.errf(err, "Failed to create MapResponse")
		http.Error(m.w, "", http.StatusInternalServerError)

		return
	}

	m.w.Header().Set("Content-Type", "application/json; charset=utf-8")
	m.w.WriteHeader(http.StatusOK)
	_, err = m.w.Write(mapResp)
	if err != nil {
		m.errf(err, "Failed to write response")
	}

	m.flush200()
}

func logTracePeerChange(hostname string, hostinfoChange bool, change *tailcfg.PeerChange) {
	trace := log.Trace().Str("node_id", change.NodeID.String()).Str("hostname", hostname)

	if change.Key != nil {
		trace = trace.Str("node_key", change.Key.ShortString())
	}

	if change.DiscoKey != nil {
		trace = trace.Str("disco_key", change.DiscoKey.ShortString())
	}

	if change.Online != nil {
		trace = trace.Bool("online", *change.Online)
	}

	if change.Endpoints != nil {
		eps := make([]string, len(change.Endpoints))
		for idx, ep := range change.Endpoints {
			eps[idx] = ep.String()
		}

		trace = trace.Strs("endpoints", eps)
	}

	if hostinfoChange {
		trace = trace.Bool("hostinfo_changed", hostinfoChange)
	}

	if change.DERPRegion != 0 {
		trace = trace.Int("derp_region", change.DERPRegion)
	}

	trace.Time("last_seen", *change.LastSeen).Msg("PeerChange received")
}

func peerChangeEmpty(chng tailcfg.PeerChange) bool {
	return chng.Key == nil &&
		chng.DiscoKey == nil &&
		chng.Online == nil &&
		chng.Endpoints == nil &&
		chng.DERPRegion == 0 &&
		chng.LastSeen == nil &&
		chng.KeyExpiry == nil
}

func logPollFunc(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
) (func(string, ...any), func(string, ...any), func(string, ...any), func(error, string, ...any)) {
	return func(msg string, a ...any) {
			log.Warn().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey.ShortString()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(msg string, a ...any) {
			log.Info().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey.ShortString()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(msg string, a ...any) {
			log.Trace().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey.ShortString()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(err error, msg string, a ...any) {
			log.Error().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey.ShortString()).
				Str("node", node.Hostname).
				Err(err).
				Msgf(msg, a...)
		}
}

// hostInfoChanged reports if hostInfo has changed in two ways,
// - first bool reports if an update needs to be sent to nodes
// - second reports if there has been changes to routes
// the caller can then use this info to save and update nodes
// and routes as needed.
func hostInfoChanged(old, new *tailcfg.Hostinfo) (bool, bool) {
	if old.Equal(new) {
		return false, false
	}

	// Routes
	oldRoutes := old.RoutableIPs
	newRoutes := new.RoutableIPs

	sort.Slice(oldRoutes, func(i, j int) bool {
		return comparePrefix(oldRoutes[i], oldRoutes[j]) > 0
	})
	sort.Slice(newRoutes, func(i, j int) bool {
		return comparePrefix(newRoutes[i], newRoutes[j]) > 0
	})

	if !xslices.Equal(oldRoutes, newRoutes) {
		return true, true
	}

	// Services is mostly useful for discovery and not critical,
	// except for peerapi, which is how nodes talk to eachother.
	// If peerapi was not part of the initial mapresponse, we
	// need to make sure its sent out later as it is needed for
	// Taildrop.
	// TODO(kradalby): Length comparison is a bit naive, replace.
	if len(old.Services) != len(new.Services) {
		return true, false
	}

	return false, false
}

// TODO(kradalby): Remove after go 1.23, will be in stdlib.
// Compare returns an integer comparing two prefixes.
// The result will be 0 if p == p2, -1 if p < p2, and +1 if p > p2.
// Prefixes sort first by validity (invalid before valid), then
// address family (IPv4 before IPv6), then prefix length, then
// address.
func comparePrefix(p, p2 netip.Prefix) int {
	if c := cmp.Compare(p.Addr().BitLen(), p2.Addr().BitLen()); c != 0 {
		return c
	}
	if c := cmp.Compare(p.Bits(), p2.Bits()); c != 0 {
		return c
	}
	return p.Addr().Compare(p2.Addr())
}
