package state

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// c2nTimeout bounds how long a c2n request waits for the node to answer.
// For an update, the node replies once the update has started, not finished.
// It stays well under the server's write timeout, so an API answers first.
const c2nTimeout = 10 * time.Second

// Why a node did not start a client update; the words are v0's
// details.reason of update_refused.
const (
	UpdateNotConnected    = "notConnected"
	UpdateNotAllowed      = "updatesNotAllowed"
	UpdateRefusedByClient = "clientRefused"
	UpdateAnswerNotInTime = "timeout"
)

var (
	// ErrC2NBadAnswer is a c2n answer that is not a 200 or cannot be read.
	ErrC2NBadAnswer = errors.New("node answered the c2n request with an error")
	// ErrShuttingDown is a c2n request that the server's shutdown ended.
	ErrShuttingDown = errors.New("server is shutting down")
)

// ClientUpdateRefusedError is a client update the node did not start.
type ClientUpdateRefusedError struct {
	// Reason is one of the Update* words.
	Reason string
	// ClientError is the text the client sent with its refusal.
	ClientError string
	// Err is the cause, such as [ErrC2NBadAnswer]; nil when the node said
	// why.
	Err error
}

func (e *ClientUpdateRefusedError) Error() string {
	msg := "client update not started: " + e.Reason
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}

	return msg
}

func (e *ClientUpdateRefusedError) Unwrap() error { return e.Err }

// RequestClientUpdate asks the node over c2n to update its Tailscale client.
// connected is whether the node has a live map stream, which alone can carry
// the request; send delivers the ping that carries it. A node that does not
// start the update is a [*ClientUpdateRefusedError] that says why.
//
// One request is in flight for a node at a time; a call that comes while
// one is shares its answer, so callers cannot flood a node with pings.
func (s *State) RequestClientUpdate(
	ctx context.Context,
	nodeID types.NodeID,
	connected bool,
	send func(...change.Change),
) error {
	if ctx.Err() != nil {
		return &ClientUpdateRefusedError{Reason: UpdateAnswerNotInTime, Err: ctx.Err()}
	}

	flight := s.clientUpdates.DoChan(nodeID.String(), func() (any, error) {
		// The callers who share the answer outlive any one of them;
		// c2nTimeout bounds the request.
		return nil, s.requestClientUpdate(context.WithoutCancel(ctx), nodeID, connected, send)
	})

	select {
	case r := <-flight:
		return r.Err
	case <-ctx.Done():
		return &ClientUpdateRefusedError{Reason: UpdateAnswerNotInTime, Err: ctx.Err()}
	}
}

func (s *State) requestClientUpdate(
	ctx context.Context,
	nodeID types.NodeID,
	connected bool,
	send func(...change.Change),
) error {
	node, ok := s.GetNodeByID(nodeID)
	if !ok {
		return fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	hi := node.Hostinfo()

	switch {
	case !hi.Valid():
		return &ClientUpdateRefusedError{Reason: UpdateNotConnected}
	case !hi.AllowsUpdate():
		return &ClientUpdateRefusedError{Reason: UpdateNotAllowed}
	case !connected:
		return &ClientUpdateRefusedError{Reason: UpdateNotConnected}
	}

	raw, req, err := s.sendC2N(ctx, nodeID, "/update", send)
	if err != nil {
		return err
	}

	res, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req)
	if err != nil {
		return refusedBadAnswer(fmt.Errorf("%w: reading: %w", ErrC2NBadAnswer, err))
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		// The status text is the node's; it is logged clean, not echoed.
		log.Info().Uint64(zf.NodeID, nodeID.Uint64()).Str("status", cleanClientText(res.Status)).Msg("node answered c2n request with an error")

		return refusedBadAnswer(ErrC2NBadAnswer)
	}

	var update tailcfg.C2NUpdateResponse

	err = json.NewDecoder(res.Body).Decode(&update)
	if err != nil {
		return refusedBadAnswer(fmt.Errorf("%w: decoding: %w", ErrC2NBadAnswer, err))
	}

	if !update.Started {
		clientError := cleanClientText(update.Err)

		log.Info().EmbedObject(node).Str("reason", clientError).Msg("node refused client update")

		return &ClientUpdateRefusedError{Reason: UpdateRefusedByClient, ClientError: clientError}
	}

	s.ClientUpdateStarted(nodeID, hi.IPNVersion())

	return nil
}

// maxClientText bounds a text a node sends that reaches an admin.
const maxClientText = 256

// cleanClientText is text a node sent, fit to show an admin and to log: no
// control or bidirectional formatting character, which could rewrite a
// terminal or reorder what follows, valid UTF-8, and at most maxClientText
// bytes and an ellipsis. Any owner of a node controls it.
func cleanClientText(text string) string {
	text = strings.Map(func(r rune) rune {
		if types.ValidateUserText(string(r)) != nil {
			return utf8.RuneError
		}

		return r
	}, strings.ToValidUTF8(text, string(utf8.RuneError)))

	if len(text) <= maxClientText {
		return text
	}

	cut := maxClientText
	for !utf8.RuneStart(text[cut]) {
		cut--
	}

	return text[:cut] + "…"
}

// refusedBadAnswer is an answer that says no more than that the node did not
// start the update.
func refusedBadAnswer(err error) error {
	return &ClientUpdateRefusedError{Reason: UpdateRefusedByClient, Err: err}
}

// sendC2N sends a POST to path on the node's c2n handler, carried in a
// [tailcfg.PingRequest], and waits for the node's raw HTTP response.
func (s *State) sendC2N(
	ctx context.Context,
	nodeID types.NodeID,
	path string,
	send func(...change.Change),
) ([]byte, *http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://headscale"+path, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("building c2n request: %w", err)
	}

	var payload bytes.Buffer

	err = req.Write(&payload)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding c2n request: %w", err)
	}

	// The client only answers c2n over Noise, and only an https URL makes
	// its Noise transport dial; the host is not used.
	callback, err := url.Parse(s.cfg.ServerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing server_url: %w", err)
	}

	c2nID, responseCh := s.RegisterC2N(nodeID)
	defer s.CancelC2N(c2nID)

	callback.Scheme = "https"
	callback.Path = "/machine/c2n-response"
	callback.RawQuery = url.Values{"id": {c2nID}}.Encode()

	send(change.PingNode(nodeID, &tailcfg.PingRequest{
		URL:     callback.String(),
		Log:     true,
		Types:   "c2n",
		Payload: payload.Bytes(),
	}))

	timer := time.NewTimer(c2nTimeout)
	defer timer.Stop()

	select {
	case raw, ok := <-responseCh:
		if !ok {
			return nil, nil, ErrShuttingDown
		}

		return raw, req, nil
	case <-timer.C:
		return nil, nil, &ClientUpdateRefusedError{Reason: UpdateAnswerNotInTime}
	case <-ctx.Done():
		return nil, nil, &ClientUpdateRefusedError{Reason: UpdateAnswerNotInTime, Err: ctx.Err()}
	}
}
