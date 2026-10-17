package testcapture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

// Step is one mutating action in a multi-step capture and what the tailnet
// showed once it settled.
type Step struct {
	Name string `json:"name"`

	// At is the step mark. Key expiry seen in the step is judged against it.
	At time.Time `json:"at"`

	Note string `json:"note,omitempty"`

	// Result is one of observed, expected-refusal, setup-failed, timeout,
	// not-converged or capture-failed. Only observed and expected-refusal
	// steps carry data a consumer may assert on.
	Result string `json:"result"`

	Actions []Action `json:"actions,omitempty"`

	// Captures holds node state after the barrier, keyed by alias.
	Captures map[string]Node `json:"captures,omitempty"`

	// Register and Frames are keyed by alias, in log order.
	Register map[string][]RegisterAttempt `json:"register,omitempty"`
	Frames   map[string][]Frame           `json:"frames,omitempty"`
}

// Action is one thing the capture tool did in a step: a client command, an
// API exchange or a wait. Keys, OAuth clients, devices and auth URLs appear as
// labels, never as values.
type Action struct {
	// Kind is join, relogin, logout, restart, kill, start, cli, api, token,
	// policy, wait, retire and so on.
	Kind string `json:"kind"`
	Node string `json:"node,omitempty"`

	// Key and Client are the auth key and OAuth client labels used or created.
	Key    string `json:"key,omitempty"`
	Client string `json:"client,omitempty"`

	// Principal is admin, user:<name> or token:<client>.
	Principal string `json:"principal,omitempty"`

	Force bool `json:"force,omitempty"`

	// RequestTags is nil when no tags were sent and empty when an empty
	// list was.
	RequestTags *[]string `json:"request_tags,omitempty"`

	// Scope is a token request's scope field byte for byte, so order and
	// repeats survive. It is nil when the form had none.
	Scope *string `json:"scope,omitempty"`

	Routes   []string `json:"routes,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	Args     []string `json:"args,omitempty"`

	// Path uses placeholders such as {device:x}, {key:K} and {client:C}.
	Method string            `json:"method,omitempty"`
	Path   string            `json:"path,omitempty"`
	Header map[string]string `json:"header,omitempty"`

	// Body and Response hold JSON as sent and received. Other bytes, such as
	// HuJSON, are stored as a JSON string, and "" is a zero-length body.
	// A token action never sets Body: the form carries the client secret,
	// so Client, Scope and RequestTags stand for it.
	Body       json.RawMessage   `json:"body,omitempty"`
	Status     int               `json:"status,omitempty"`
	RespHeader map[string]string `json:"resp_header,omitempty"`
	Response   json.RawMessage   `json:"response,omitempty"`

	Exit   *int   `json:"exit,omitempty"`
	Output string `json:"output,omitempty"`

	// OffsetMS is relative to [Step.At]. It only tells an action sent in the
	// same tick from one sent after settling.
	OffsetMS int64 `json:"offset_ms,omitempty"`
}

// RegisterAttempt is one /machine/register exchange as tailscaled logs it,
// or a login error the client logged on its own. Node keys and auth URLs
// are labels in a written capture.
type RegisterAttempt struct {
	NodeKey    string `json:"node_key,omitempty"`
	OldNodeKey string `json:"old_node_key,omitempty"`
	Followup   bool   `json:"followup,omitempty"`

	// NodeKeyExpired and MachineAuthorized are nil until the client logs
	// the answer, so an attempt still in flight reads as unanswered.
	NodeKeyExpired    *bool  `json:"node_key_expired,omitempty"`
	MachineAuthorized *bool  `json:"machine_authorized,omitempty"`
	AuthURL           string `json:"auth_url,omitempty"`

	Err string `json:"err,omitempty"`

	// OffsetMS is relative to [Step.At].
	OffsetMS int64 `json:"offset_ms,omitempty"`
}

// The leading [^"]* rejects tailscaled's JSON echoes of the same lines.
var (
	registerReqRE  = regexp.MustCompile(`^[^"]*RegisterReq: onode=(\S*) node=(\S*) fup=(true|false) nks=(?:true|false)$`)
	registerRespRE = regexp.MustCompile(`^[^"]*RegisterReq: got response; nodeKeyExpired=(true|false), machineAuthorized=(true|false); authURL=(?:true|false)$`)
	authURLRE      = regexp.MustCompile(`^[^"]*AuthURL is (\S+)$`)
	loginErrRE     = regexp.MustCompile(`^[^"]*(?:TryLogin|WaitLoginURL): (.+)$`)
)

// AppendRegisterLine folds one tailscaled log line into attempts and reports
// whether it was a register line. A request line starts an attempt; the
// answer and the "AuthURL is" line complete the last one. A login error is
// its own entry, because it can come before any request is sent. Node keys
// and the URL come back raw; callers label them before writing.
func AppendRegisterLine(attempts []RegisterAttempt, line string) ([]RegisterAttempt, bool) {
	line = strings.TrimRight(line, "\r\n")

	if m := registerReqRE.FindStringSubmatch(line); m != nil {
		return append(attempts, RegisterAttempt{
			OldNodeKey: m[1],
			NodeKey:    m[2],
			Followup:   m[3] == "true",
		}), true
	}

	if m := registerRespRE.FindStringSubmatch(line); m != nil {
		if n := len(attempts); n == 0 || attempts[n-1].MachineAuthorized != nil || attempts[n-1].Err != "" {
			attempts = append(attempts, RegisterAttempt{})
		}

		last := &attempts[len(attempts)-1]
		last.NodeKeyExpired = new(m[1] == "true")
		last.MachineAuthorized = new(m[2] == "true")

		return attempts, true
	}

	if m := authURLRE.FindStringSubmatch(line); m != nil {
		if len(attempts) == 0 {
			attempts = append(attempts, RegisterAttempt{})
		}

		attempts[len(attempts)-1].AuthURL = m[1]

		return attempts, true
	}

	if m := loginErrRE.FindStringSubmatch(line); m != nil {
		return append(attempts, RegisterAttempt{Err: m[1]}), true
	}

	return attempts, false
}

// Frame is one map message on a node's stream.
type Frame struct {
	// OffsetMS is relative to [Step.At].
	OffsetMS int64 `json:"offset_ms"`

	// Request with Stream set marks the start of a stream.
	Request  *tailcfg.MapRequest  `json:"request,omitempty"`
	Response *tailcfg.MapResponse `json:"response,omitempty"`

	// Empty maps each key the raw response held as [], {} or null to that
	// literal: top-level keys, and patch fields as
	// "PeersChangedPatch[i].<field>"; see [ParseMapResponse].
	Empty map[string]string `json:"empty,omitempty"`

	// Dropped names top-level fields cut for size, such as DERPMap.
	Dropped []string `json:"dropped,omitempty"`
}

// ParseMapResponse decodes a MapResponse body as the server sent it. Typed
// marshalling omits empty top-level slices and maps, yet an empty
// PacketFilter blocks everything while an absent one keeps the last, so
// [Frame.Empty] keeps what the raw body held. Patch fields count too: the
// client applies a patch's Endpoints: [] or CapMap: {}, but skips absent ones.
func ParseMapResponse(raw []byte) (Frame, error) {
	var resp tailcfg.MapResponse

	err := json.Unmarshal(raw, &resp)
	if err != nil {
		return Frame{}, fmt.Errorf("testcapture: map response: %w", err)
	}

	var top map[string]json.RawMessage

	err = json.Unmarshal(raw, &top)
	if err != nil {
		return Frame{}, fmt.Errorf("testcapture: map response keys: %w", err)
	}

	var patches []map[string]json.RawMessage

	if v, ok := top["PeersChangedPatch"]; ok {
		err = json.Unmarshal(v, &patches)
		if err != nil {
			return Frame{}, fmt.Errorf("testcapture: map response patches: %w", err)
		}
	}

	f := Frame{Response: &resp}
	keep := func(k string, v json.RawMessage) {
		switch s := string(bytes.Join(bytes.Fields(v), nil)); s {
		case "[]", "{}", "null":
			if f.Empty == nil {
				f.Empty = make(map[string]string)
			}

			f.Empty[k] = s
		}
	}

	for k, v := range top {
		keep(k, v)
	}

	for i, p := range patches {
		for k, v := range p {
			keep(fmt.Sprintf("PeersChangedPatch[%d].%s", i, k), v)
		}
	}

	return f, nil
}
