package apiv0

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// AuthRequest is a registration or an SSH check that waits for an answer.
// Its ID is a secret: whoever has it may answer the request.
type AuthRequest struct {
	ID          string                 `doc:"The auth ID that the machine shows, a secret; it starts with hskey-authreq-." json:"id"`
	Kind        AuthRequestKind        `json:"kind"`
	Hostname    string                 `doc:"The hostname a registering node reports; \"\" for an SSH check."              json:"hostname"`
	Source      *SSHCheckNodeReference `doc:"The node an SSH check is from; null for a registration."                      json:"source"`
	Destination *SSHCheckNodeReference `doc:"The node an SSH check is to; null for a registration."                        json:"destination"`
}

// SSHCheckNodeReference is a [NodeReference] that may be null: a node of an
// SSH check. Its name is "" when the node is gone. Huma cannot make a field
// that refers to a schema nullable, so the shape has a second name.
type SSHCheckNodeReference struct {
	_    struct{} `nullable:"true"`
	ID   string   `json:"id"`
	Name string   `json:"name"`
}

// AuthRequestKind is what an auth request asks.
type AuthRequestKind string

const (
	AuthRequestRegistration AuthRequestKind = "registration"
	AuthRequestSSHCheck     AuthRequestKind = "sshCheck"
)

func (AuthRequestKind) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{
		Type:        huma.TypeString,
		Enum:        []any{string(AuthRequestRegistration), string(AuthRequestSSHCheck)},
		Description: "registration is answered with register or reject, sshCheck with approve or reject. A client must accept a kind it does not know.",
	}
}

// RegisterAuthRequestBody is the body of POST /auth-requests/{id}/register.
type RegisterAuthRequestBody struct {
	UserID string `doc:"The user the new node belongs to." json:"userId" maxLength:"20"`
}

func (b *RegisterAuthRequestBody) fieldErrors() []FieldError {
	_, err := pathID[types.UserID](b.UserID)
	if err != nil {
		return []FieldError{{Location: userIDField, Message: notUserID}}
	}

	return nil
}

// CreateDebugNodeBody is the body of POST /debug/nodes.
type CreateDebugNodeBody struct {
	AuthID   string   `doc:"The auth ID of the request, as the machine shows it; it starts with hskey-authreq-." json:"authId"   maxLength:"64"`
	Hostname string   `doc:"The hostname the made-up node reports."                                              json:"hostname" maxLength:"255" minLength:"1"`
	Routes   []string `doc:"IP prefixes the node advertises once it is registered."                              json:"routes"   maxItems:"1024" nullable:"false"`
}

func (b *CreateDebugNodeBody) fieldErrors() []FieldError {
	var errs []FieldError

	_, err := types.AuthIDFromString(b.AuthID)
	if err != nil {
		errs = append(errs, FieldError{Location: "body.authId", Message: "is not an auth ID: hskey-authreq- and 24 lower-case hex digits"})
	}

	if types.ValidateUserText(b.Hostname) != nil {
		errs = append(errs, FieldError{Location: "body.hostname", Message: hasControlCharacter})
	}

	for i, r := range b.Routes {
		p, err := netip.ParsePrefix(r)
		if err == nil {
			err = util.CheckRouteMasked(p)
		}

		if err != nil {
			errs = append(errs, FieldError{Location: "body.routes[" + strconv.Itoa(i) + "]", Message: "is not an IP prefix with no host bits"})
		}
	}

	return errs
}

const (
	maxRegisterBody  = 1 << 10
	maxDebugNodeBody = 64 << 10
)

// tokenCannotApproveSSHCheck keeps a token from answering yes for a
// person: an SSH check is a person confirming who they are. It may reject.
var tokenCannotApproveSSHCheck = tokenRule{
	name:       "token_cannot_approve_ssh_check",
	why:        "An OAuth access token cannot approve an SSH check, whatever its scopes: the check is a person confirming who they are. It may reject one. Use an API key or the unix socket.",
	everyToken: true,
}

// tokenCannotRegisterNodeToUser keeps a token from putting a machine into
// a person's tailnet: a token stands for a client, never for a person.
var tokenCannotRegisterNodeToUser = tokenRule{
	name:       "token_cannot_register_node_to_user",
	why:        "An OAuth access token cannot register a node to a user, whatever its scopes. Use an API key or the unix socket.",
	everyToken: true,
}

type (
	authRequestIDInput struct {
		ID string `doc:"The auth ID, a secret." path:"id"`
	}

	registerAuthRequestInput struct {
		ID   string `doc:"The auth ID, a secret." path:"id"`
		Body RegisterAuthRequestBody
	}

	registeredNodeOutput struct {
		Location string `header:"Location"`
		ETag     string `doc:"The revision of the node, quoted." header:"ETag"`
		Body     Node
	}

	createDebugNodeInput struct {
		Body CreateDebugNodeBody
	}
)

var (
	// Answered, timed out and never made look alike: each is a secret's
	// absence, and the detail must not tell a guess from a stale ID.
	authRequestGone = onError(db.ErrNodeNotFoundRegistrationCache, CodeNotFound, "No auth request has this ID. It may have timed out, or it was answered already.")
	authRequestKind = onError(state.ErrAuthRequestKind, CodeAuthRequestKind, "The auth request is of another kind; details.kind says which.")
)

// registrationProblem is the answer to an error of a registration that is
// not a fault of the server, or nil. The request still waits after each.
func registrationProblem(err error) *Problem {
	var tags *state.TagsNotPermittedError

	switch {
	case errors.As(err, &tags):
		p := newProblem(CodeTagsNotPermitted, "The node asks for tags its user may not give; details.tags names them.")
		p.Details["tags"] = tags.Tags

		return p
	case errors.Is(err, state.ErrNodeKeyInUse):
		p := newProblem(CodeRegistrationRefused, "Another machine has the node key this one sent.")
		p.Details["reason"] = refusedNodeKeyInUse

		return p
	case errors.Is(err, types.ErrHostinfoTooLarge):
		p := newProblem(CodeRegistrationRefused, "With this registration the node's report is over the limit.")
		p.Details["reason"] = refusedReportTooLarge

		return p
	}

	return nil
}

// The reasons of registration_refused.
const (
	refusedNodeKeyInUse   = "nodeKeyInUse"
	refusedReportTooLarge = "reportTooLarge"
)

func registerAuthRequests(api huma.API, b Backend) {
	tags := []string{"Auth requests"}

	register(api, huma.Operation{
		OperationID: "getAuthRequest",
		Method:      http.MethodGet,
		Path:        Prefix + "/auth-requests/{id}",
		Summary:     "Read a waiting auth request",
		Description: "There is no list: the auth ID is a secret the node hands to one person. A request that timed out or was answered is not_found.",
		Tags:        tags,
	}, needs(scope.DevicesCoreRead), []answer{authRequestGone}, func(_ context.Context, in *authRequestIDInput) (*struct{ Body AuthRequest }, error) {
		id, req, err := b.waitingAuthRequest(in.ID)
		if err != nil {
			return nil, err
		}

		return &struct{ Body AuthRequest }{Body: b.authRequest(id, req)}, nil
	})

	register(api, huma.Operation{
		OperationID:   "registerAuthRequest",
		Method:        http.MethodPost,
		Path:          Prefix + "/auth-requests/{id}/register",
		Summary:       "Register the node of a registration to a user",
		Description:   "Answers a registration: the node joins as the user's, or tagged when it asks for tags the user may give. An SSH check is auth_request_kind. An OAuth access token cannot register a node to a user. After invalid_field, tags_not_permitted or registration_refused the request still waits; one that timed out meanwhile is not_found.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  maxRegisterBody,
	}, needs(scope.DevicesCore).withTokenRules(&tokenCannotRegisterNodeToUser), []answer{
		authRequestGone, authRequestKind, {code: CodeTagsNotPermitted}, {code: CodeRegistrationRefused},
	},
		func(ctx context.Context, in *registerAuthRequestInput) (*registeredNodeOutput, error) {
			id, req, err := b.waitingAuthRequest(in.ID)
			if err != nil {
				return nil, err
			}

			uid, _ := pathID[types.UserID](in.Body.UserID) // checked in fieldErrors

			nv, c, err := b.State.HandleNodeFromAuthPath(id, uid, nil, util.RegisterMethodCLI)
			b.Change(c)

			switch {
			case errors.Is(err, db.ErrUserNotFound):
				p := newProblem(CodeInvalidField, "A field is not valid.")
				p.Errors = []FieldError{{Location: userIDField, Message: "no user has this ID"}}

				return nil, p
			case registrationProblem(err) != nil:
				p := registrationProblem(err)
				p.Object = new(authRequestObject(req))

				return nil, p
			case err != nil && nv.Valid():
				// The node is registered; what failed came after.
				log.Error().Err(err).Str(zf.RequestID, middleware.GetReqID(ctx)).Msg("api v0: after a registration")
			case err != nil:
				return nil, b.authRequestProblem(err, req)
			}

			out, err := b.nodeOutput(nv.ID(), nv)
			if err != nil {
				return nil, err
			}

			return &registeredNodeOutput{Location: Prefix + "/nodes/" + out.Body.ID, ETag: out.ETag, Body: out.Body}, nil
		})

	for _, verb := range []struct {
		id, path, summary, description string
		approve                        bool
		access                         access
		answers                        []answer
	}{
		{
			"approveAuthRequest", "approve", "Approve an SSH check",
			"Answers an SSH check with yes. A registration is auth_request_kind; register it to a user. An OAuth access token cannot approve an SSH check.", true,
			needs(scope.DevicesCore).withTokenRules(&tokenCannotApproveSSHCheck),
			[]answer{authRequestGone, authRequestKind},
		},
		{
			"rejectAuthRequest", "reject", "Reject an auth request", "Answers a registration or an SSH check with no.", false,
			needs(scope.DevicesCore),
			[]answer{authRequestGone},
		},
	} {
		register(api, huma.Operation{
			OperationID:   verb.id,
			Method:        http.MethodPost,
			Path:          Prefix + "/auth-requests/{id}/" + verb.path,
			Summary:       verb.summary,
			Description:   verb.description,
			Tags:          tags,
			DefaultStatus: http.StatusNoContent,
		}, verb.access, verb.answers, func(_ context.Context, in *authRequestIDInput) (*struct{}, error) {
			id, req, err := b.waitingAuthRequest(in.ID)
			if err != nil {
				return nil, err
			}

			err = b.State.AnswerAuthRequest(id, verb.approve)
			if err != nil {
				return nil, b.authRequestProblem(err, req)
			}

			return &struct{}{}, nil
		})
	}

	register(api, huma.Operation{
		OperationID:   "createDebugNode",
		Method:        http.MethodPost,
		Path:          Prefix + "/debug/nodes",
		Summary:       "Make a registration for a made-up node",
		Description:   "A test tool. It makes an auth request, not a node: a registration of a made-up machine that advertises routes, which register answers. It has no Location, which would hold the auth ID, a secret. An ID that a request has is invalid_field at body.authId; a server that holds as many auth requests as it may is unhealthy, with the reason auth_requests_full.",
		Tags:          []string{"Debug"},
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  maxDebugNodeBody,
	}, needs(scope.All), nil, func(_ context.Context, in *createDebugNodeInput) (*struct{ Body AuthRequest }, error) {
		body := in.Body
		id, _ := types.AuthIDFromString(body.AuthID) // checked in fieldErrors

		routes := make([]netip.Prefix, len(body.Routes))
		for i, r := range body.Routes {
			routes[i] = netip.MustParsePrefix(r) // checked in fieldErrors
		}

		req := types.NewRegisterAuthRequest(&types.RegistrationData{
			MachineKey: key.NewMachine().Public(),
			NodeKey:    key.NewNode().Public(),
			Hostname:   body.Hostname,
			Hostinfo:   &tailcfg.Hostinfo{Hostname: body.Hostname, RoutableIPs: routes},
		})

		err := b.State.SetAuthCacheEntry(id, req)
		if errors.Is(err, state.ErrAuthCacheFull) {
			return nil, unhealthy("The server holds as many auth requests as it may; try again later.", ReasonAuthRequestsFull)
		}

		if errors.Is(err, state.ErrAuthCacheEntryExists) {
			p := newProblem(CodeInvalidField, "A field is not valid.")
			p.Errors = []FieldError{{Location: "body.authId", Message: "an auth request has this ID"}}

			return nil, p
		}

		if err != nil {
			return nil, err
		}

		return &struct{ Body AuthRequest }{Body: b.authRequest(id, req)}, nil
	})
}

// waitingAuthRequest is the auth request of a path that waits for an
// answer. A path of another form is not_found before anything is read.
// The object of not_found names the kind and no ID: the ID is the secret.
func (b Backend) waitingAuthRequest(path string) (types.AuthID, *types.AuthRequest, error) {
	id, err := types.AuthIDFromString(path)
	if err != nil {
		return "", nil, newProblem(CodeNotFound, "Nothing has this ID. An auth ID is hskey-authreq- and 24 lower-case hex digits.")
	}

	req, ok := b.State.AuthRequest(id)
	if !ok {
		return "", nil, about(db.ErrNodeNotFoundRegistrationCache, authRequestObject(nil))
	}

	return id, req, nil
}

// authRequestProblem is err of an answer to req, with its object, and for
// auth_request_kind the kind req is.
func (b Backend) authRequestProblem(err error, req *types.AuthRequest) error {
	// Answered by another since it was read: gone has one form.
	if errors.Is(err, db.ErrNodeNotFoundRegistrationCache) {
		req = nil
	}

	if errors.Is(err, state.ErrAuthRequestKind) {
		err = &detailsError{err: err, details: map[string]any{"kind": kindOf(req)}}
	}

	return about(err, authRequestObject(req))
}

// authRequestObject names an auth request in a problem: never by its ID,
// which is the secret, and by the hostname of a registration.
func authRequestObject(req *types.AuthRequest) ProblemObject {
	obj := ProblemObject{Kind: "authRequest"}
	if req != nil && req.IsRegistration() {
		obj.Name = req.RegistrationData().Hostname
	}

	return obj
}

func kindOf(req *types.AuthRequest) AuthRequestKind {
	if req.IsSSHCheck() {
		return AuthRequestSSHCheck
	}

	return AuthRequestRegistration
}

func (b Backend) authRequest(id types.AuthID, req *types.AuthRequest) AuthRequest {
	out := AuthRequest{ID: id.Raw(), Kind: kindOf(req)}

	if req.IsRegistration() {
		out.Hostname = req.RegistrationData().Hostname

		return out
	}

	binding := req.SSHCheckBinding()
	out.Source = b.authRequestNode(binding.SrcNodeID)
	out.Destination = b.authRequestNode(binding.DstNodeID)

	return out
}

func (b Backend) authRequestNode(id types.NodeID) *SSHCheckNodeReference {
	n := &SSHCheckNodeReference{ID: strconv.FormatUint(uint64(id), 10)}
	if nv, ok := b.State.GetNodeByID(id); ok {
		n.Name = nv.GivenName()
	}

	return n
}
