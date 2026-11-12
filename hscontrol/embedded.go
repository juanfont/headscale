package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/net/netx"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
)

// An embedded node is a tsnet node headscale runs in its own process, joined
// to its own tailnet with a tagged pre-auth key it mints itself. It is the
// pattern for tailnet apps shipped inside headscale; tailsql is the first.

// embeddedKeyTTL bounds a minted key: it is used within seconds, and a leaked
// one should not outlive the join.
const embeddedKeyTTL = 5 * time.Minute

// embeddedControlAddr is where embedded nodes find control on headscale's
// in-memory network. It is an IP literal because tsnet resolves hostnames
// before calling SystemDial.
const embeddedControlAddr = "127.0.0.1:80"

var errEmbeddedNeedsLogin = errors.New("embedded node needs login")

// newEmbeddedNode starts a tsnet node named hostname with tag on headscale's
// own tailnet and keeps it joined until ctx ends. dir holds its identity; dial
// reaches the control server at controlURL. The caller closes the server.
func newEmbeddedNode(
	ctx context.Context,
	st *state.State,
	dial netx.DialFunc,
	controlURL, dir, hostname, tag string,
) (*tsnet.Server, error) {
	// Headscale tells clients to stop log upload, but only once connected.
	envknob.SetNoLogsNoSupport()

	logf := util.TSLogfWrapper()

	stateStore, err := store.New(logf, filepath.Join(dir, "tailscaled.state"))
	if err != nil {
		return nil, fmt.Errorf("opening state for %s: %w", hostname, err)
	}

	// Mint only when headscale does not know this identity, so restarts do not
	// leave a used key behind each time.
	var authKey string

	if !embeddedNodeRegistered(st, stateStore, tag) {
		warnStaleEmbeddedNodes(st, hostname, tag)

		authKey, err = mintEmbeddedKey(st, tag)
		if err != nil {
			return nil, err
		}
	}

	ts := &tsnet.Server{
		Dir:        dir,
		Store:      stateStore,
		Hostname:   hostname,
		ControlURL: controlURL,
		AuthKey:    authKey,
		SystemDial: dial,
		Logf:       logger.Discard,
		UserLogf:   logf,
	}

	_, err = ts.Up(ctx)
	if err != nil {
		ts.Close()

		return nil, fmt.Errorf("joining %s to the tailnet: %w", hostname, err)
	}

	go keepEmbeddedNodeJoined(ctx, st, ts, tag)

	return ts, nil
}

// embeddedNodeRegistered reports whether headscale holds a node with tag for
// the machine key in stateStore.
func embeddedNodeRegistered(st *state.State, stateStore ipn.StateStore, tag string) bool {
	raw, err := stateStore.ReadState(ipn.MachineKeyStateKey)
	if err != nil {
		return false
	}

	var mk key.MachinePrivate

	err = mk.UnmarshalText(raw)
	if err != nil {
		return false
	}

	for _, nv := range st.GetNodesByMachineKeyAllUsers(mk.Public()) {
		if nv.HasTag(tag) {
			return true
		}
	}

	return false
}

func mintEmbeddedKey(st *state.State, tag string) (string, error) {
	exp := time.Now().Add(embeddedKeyTTL)

	pak, err := st.CreatePreAuthKey(nil, false, false, &exp, []string{tag})
	if err != nil {
		return "", fmt.Errorf("minting key for %s: %w", tag, err)
	}

	return pak.Key, nil
}

// warnStaleEmbeddedNodes names nodes left from a lost identity: the new node
// cannot take their name, so it registers as hostname-1.
func warnStaleEmbeddedNodes(st *state.State, hostname, tag string) {
	for _, nv := range st.ListNodes().All() {
		if nv.HasTag(tag) && nv.Hostname() == hostname {
			log.Warn().
				Uint64("node.id", nv.ID().Uint64()).
				Str("node.name", nv.GivenName()).
				Msgf("%s registers a new identity; delete the old node to free its name", hostname)
		}
	}
}

// keepEmbeddedNodeJoined re-joins the node when control forgets it, such as
// after an admin deletes it. tsnet does not re-login on its own.
func keepEmbeddedNodeJoined(ctx context.Context, st *state.State, ts *tsnet.Server, tag string) {
	lc, err := ts.LocalClient()
	if err != nil {
		log.Error().Err(err).Msg("embedded node: local client")

		return
	}

	bo := backoff.NewBackoff("embedded-node", util.TSLogfWrapper(), 5*time.Minute)

	for ctx.Err() == nil {
		err := watchEmbeddedNode(ctx, lc, bo, func() error {
			k, err := mintEmbeddedKey(st, tag)
			if err != nil {
				return err
			}

			return lc.Start(ctx, ipn.Options{AuthKey: k})
		})
		if ctx.Err() != nil {
			return
		}

		log.Warn().Err(err).Str("tag", tag).Msg("embedded node: watch ended, retrying")
		bo.BackOff(ctx, err)
	}
}

func watchEmbeddedNode(ctx context.Context, lc *local.Client, bo *backoff.Backoff, rejoin func() error) error {
	w, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialState)
	if err != nil {
		return err
	}
	defer w.Close()

	for {
		n, err := w.Next()
		if err != nil {
			return err
		}

		if n.State == nil {
			continue
		}

		if *n.State == ipn.Running {
			bo.BackOff(ctx, nil)

			continue
		}

		if *n.State == ipn.NeedsLogin {
			// Space attempts out: a rejected key leads straight back here.
			bo.BackOff(ctx, errEmbeddedNeedsLogin)

			err := rejoin()
			if err != nil {
				log.Error().Err(err).Msg("embedded node: rejoining")
			}
		}
	}
}
