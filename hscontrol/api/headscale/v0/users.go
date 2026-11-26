package apiv0

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/types/views"
)

// User is a user, the same object in a list, a get and the answer to every
// write.
type User struct {
	ID            string          `json:"id"`
	Name          string          `doc:"The stored username; it can be empty for a user from OIDC."                                    json:"name"`
	LoginName     string          `doc:"What Headscale shows for the user: the email, else the name, else the provider ID. Read-only." json:"loginName"`
	DisplayName   string          `json:"displayName"`
	Email         string          `json:"email"`
	ProfilePicURL string          `json:"profilePicUrl"`
	Provider      string          `doc:"Where the user comes from. A client must accept a value it does not know."                     enum:"local,oidc" json:"provider"`
	ProviderID    string          `doc:"The identifier at the identity provider; empty for a local user."                              json:"providerId"`
	NodeCount     int             `doc:"Nodes the user owns; tagged nodes are owned by their tags and not counted."                    json:"nodeCount"`
	Nodes         []NodeReference `doc:"The same nodes, in ID order."                                                                  json:"nodes"      nullable:"false"`
	Created       time.Time       `json:"created"`
}

// NodeReference names a node by ID and name.
type NodeReference struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// DeletedUser is what a delete of a user removed, or in a dry run would
// remove: the only delete that answers with a body.
type DeletedUser struct {
	Nodes        []NodeReference `doc:"The nodes of the user, in ID order."                                                                    json:"nodes"        nullable:"false"`
	AuthKeyCount int             `doc:"The auth keys the user owns, revoked and expired ones too; tagged keys it made stay."                   json:"authKeyCount"`
	APIKeyCount  int             `doc:"The API keys the user owns, revoked and expired ones too."                                              json:"apiKeyCount"`
	Expect       string          `doc:"Stands for the user and every node and key it owns. Send it as expect to remove only what this showed." json:"expect"`
}

// UserList is a page of users.
type UserList struct {
	Users         []User `json:"users"                                                                                  nullable:"false"`
	NextPageToken string `doc:"Present when more rows can follow; send it back as pageToken. Missing on the last page." json:"nextPageToken,omitempty"`
}

// CreateUserBody is the body of POST /users. Each text has a maxLength, in
// characters, which a limit can be raised later without breaking a client
// and cannot be added. A name can have the form of an email address, so it
// takes the email's limit, the one of the mail standards (RFC 5321).
type CreateUserBody struct {
	Name          string           `doc:"The username."                  json:"name"                   maxLength:"254"`
	DisplayName   Optional[string] `json:"displayName,omitzero"          maxLength:"128"`
	Email         Optional[string] `json:"email,omitzero"                maxLength:"254"`
	ProfilePicURL Optional[string] `doc:"An absolute http or https URL." json:"profilePicUrl,omitzero" maxLength:"2048"`
}

// UpdateUserBody is the body of PATCH /users/{id}: each field that is sent
// changes, the others stay.
type UpdateUserBody struct {
	Name          Optional[string] `doc:"The username; it cannot be empty."              json:"name,omitzero"          maxLength:"254"`
	DisplayName   Optional[string] `doc:"\"\" clears it."                                json:"displayName,omitzero"   maxLength:"128"`
	Email         Optional[string] `doc:"\"\" clears it."                                json:"email,omitzero"         maxLength:"254"`
	ProfilePicURL Optional[string] `doc:"An absolute http or https URL; \"\" clears it." json:"profilePicUrl,omitzero" maxLength:"2048"`
}

// Resolve reports user checks alongside schema errors for other fields.
func (in *createUserInput) Resolve(_ huma.Context) []error {
	return checkUserFields(in.RawBody, false)
}

// Resolve checks only fields supplied by the update.
func (in *updateUserInput) Resolve(_ huma.Context) []error {
	return checkUserFields(in.RawBody, true)
}

// maxUserBody bounds a user body: four short texts.
const maxUserBody = 16 << 10

// tokenCannotChangeUserNameOrEmail keeps a token from moving a policy rule.
// A rule names a user by its name or its email; a token that could change
// both could give one user's name to another, in two calls that never make
// a clash, and the rule would follow. An API key and the socket may.
var tokenCannotChangeUserNameOrEmail = tokenRule{
	name: "token_cannot_change_user_name_or_email",
	why:  "An OAuth access token cannot change the name or the email of a user that exists, because a policy names a user by them. It can create a user, and change the display name and the picture. Use an API key.",
	refuses: func(_ *caller, in any) bool {
		u, ok := in.(*updateUserInput)

		return ok && (u.Body.Name.Set || u.Body.Email.Set)
	},
}

type (
	listUsersInput struct {
		PageQuery

		Name  string `doc:"Only users with exactly this name. More than one user can have a name." query:"name"`
		Email string `doc:"Only users with exactly this email."                                    query:"email"`
	}

	userIDInput struct {
		ID string `doc:"The ID of the user." path:"id"`
	}

	createUserInput struct {
		RawBody []byte
		Body    CreateUserBody
	}

	updateUserInput struct {
		RawBody []byte
		ID      string `doc:"The ID of the user." path:"id"`
		Body    UpdateUserBody
	}

	deleteUserInput struct {
		ID        string `doc:"The ID of the user."                                                                                                       path:"id"`
		WithNodes bool   `doc:"Delete the nodes the user owns too. Needs the scope devices:core as well as users."                                        query:"withNodes"`
		DryRun    bool   `doc:"Answer what the delete would remove, and remove nothing."                                                                  query:"dryRun"`
		Expect    string `doc:"The expect of a dry run: refuse with user_changed and remove nothing when a node or a key of the user came or went since." pattern:"^[0-9a-f]{16}$" query:"expect"`
	}

	userOutput struct{ Body User }

	createdUserOutput struct {
		Location string `header:"Location"`
		Body     User
	}
)

var (
	userNotFound = onError(db.ErrUserNotFound, CodeNotFound, "No user has this ID.")
	// The texts of a user; the user write states the holder as object.
	userTaken = []answer{
		onError(
			db.ErrUserNameTaken,
			CodeNameTaken,
			"The name equals a text of another user; object names it.",
		),
		onError(
			db.ErrUserEmailTaken,
			CodeEmailTaken,
			"The email equals a text of another user; object names it.",
		),
		// The unique index, when a write outside v0 took the name meanwhile.
		onError(
			gorm.ErrDuplicatedKey,
			CodeNameTaken,
			"Another local user has the name.",
		),
	}
)

func registerUsers(api huma.API, b Backend) {
	register(api, huma.Operation{
		OperationID: "listUsers",
		Method:      http.MethodGet,
		Path:        Prefix + "/users",
		Summary:     "List users",
		Tags:        []string{"Users"},
	}, needs(scope.UsersRead), nil, func(ctx context.Context, in *listUsersInput) (*struct{ Body UserList }, error) {
		pg, err := openPage[uint64](in.PageQuery, "users", in.Name, in.Email)
		if err != nil {
			return nil, err
		}

		// The users and the nodes they own are of one moment.
		defer b.State.UsersMoment()()

		rows, err := b.State.ListUsersPage(
			ctx,
			&types.User{Name: in.Name, Email: in.Email},
			types.UserID(pg.after),
			pg.limit(),
		)
		if err != nil {
			return nil, err
		}

		rows, next := cutPage(
			pg,
			rows,
			func(u types.User) uint64 { return uint64(u.ID) },
		)

		ids := make([]types.UserID, len(rows))
		for i := range rows {
			ids[i] = types.UserID(rows[i].ID)
		}

		owned := b.State.ListNodesByUsers(ids)

		list := UserList{Users: make([]User, 0, len(rows)), NextPageToken: next}
		for i := range rows {
			list.Users = append(list.Users, userFromView(rows[i].View(), owned[ids[i]]))
		}

		return &struct{ Body UserList }{Body: list}, nil
	})

	register(api, huma.Operation{
		OperationID: "getUser",
		Method:      http.MethodGet,
		Path:        Prefix + "/users/{id}",
		Summary:     "Read one user",
		Tags:        []string{"Users"},
	}, needs(scope.UsersRead), []answer{userNotFound}, func(ctx context.Context, in *userIDInput) (*userOutput, error) {
		id, err := pathID[types.UserID](in.ID)
		if err != nil {
			return nil, err
		}

		defer b.State.UsersMoment()()

		u, err := b.State.GetUserByIDContext(ctx, id)
		if err != nil {
			return nil, about(err, userObject(id, types.UserView{}))
		}

		return &userOutput{Body: b.user(u.View())}, nil
	})

	register(api, huma.Operation{
		OperationID:   "createUser",
		Method:        http.MethodPost,
		Path:          Prefix + "/users",
		Summary:       "Create a local user",
		Description:   "The name and the email must not equal the name, the email or the provider identifier of another user, without regard to case: a policy names a user by these texts.",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  maxUserBody,
	}, needs(scope.Users), userTaken, func(ctx context.Context, in *createUserInput) (*createdUserOutput, error) {
		body := in.Body

		u, c, err := b.State.CreateLocalUser(types.User{
			Name:          body.Name,
			DisplayName:   body.DisplayName.Value,
			Email:         body.Email.Value,
			ProfilePicURL: body.ProfilePicURL.Value,
		})
		b.Change(c)

		switch {
		case err != nil && u != nil:
			// The user is stored; what failed came after.
			log.Error().
				Err(err).
				Str(zf.RequestID, middleware.GetReqID(ctx)).
				Msg("api v0: after a user create")
		case err != nil:
			return nil, takenBy(err, body.Name, body.Email.Value)
		}

		out := b.user(u.View())

		return &createdUserOutput{Location: Prefix + "/users/" + out.ID, Body: out}, nil
	})

	register(api, huma.Operation{
		OperationID:  "updateUser",
		Method:       http.MethodPatch,
		Path:         Prefix + "/users/{id}",
		Summary:      "Change a local user",
		Description:  "Changes the fields that are sent and leaves the others, as JSON Merge Patch (RFC 7396). A user from OIDC cannot be changed. A new name or email must not equal the name, the email or the provider identifier of another user, without regard to case. An OAuth access token cannot change the name or the email.",
		Tags:         []string{"Users"},
		MaxBodyBytes: maxUserBody,
	}, needs(scope.Users).withTokenRules(&tokenCannotChangeUserNameOrEmail), append([]answer{
		userNotFound,
		onError(
			db.ErrCannotChangeOIDCUser,
			CodeUserManagedByOIDC,
			"The identity provider owns this user; change it there.",
		),
	}, userTaken...), func(ctx context.Context, in *updateUserInput) (*userOutput, error) {
		id, err := pathID[types.UserID](in.ID)
		if err != nil {
			return nil, err
		}

		body := in.Body

		u, c, err := b.State.UpdateLocalUser(id, func(u *types.User) {
			set(&u.Name, body.Name)
			set(&u.DisplayName, body.DisplayName)
			set(&u.Email, body.Email)
			set(&u.ProfilePicURL, body.ProfilePicURL)
		})
		b.Change(c)

		switch {
		case err != nil && u != nil:
			// The user is stored; what failed came after.
			log.Error().
				Err(err).
				Str(zf.RequestID, middleware.GetReqID(ctx)).
				Msg("api v0: after a user update")
		case errors.Is(err, db.ErrUserNameTaken) || errors.Is(err, db.ErrUserEmailTaken) || errors.Is(err, gorm.ErrDuplicatedKey):
			return nil, takenBy(err, body.Name.Value, body.Email.Value)
		case err != nil:
			return nil, about(err, userObject(id, b.userView(id)))
		}

		return &userOutput{Body: b.user(u.View())}, nil
	})

	register(api, huma.Operation{
		OperationID: "deleteUser",
		Method:      http.MethodDelete,
		Path:        Prefix + "/users/{id}",
		Summary:     "Delete a user",
		Description: "Removes the user with the auth keys and API keys it owns, and with withNodes=true its nodes, in one step that cannot be undone: all of it or none of it. " +
			"Tagged nodes and keys the user made stay. The answer is what was removed; with dryRun=true it is what would be, and nothing is removed. " +
			"Send the expect of a dry run to remove only what it showed. withNodes=true needs the scope devices:core as well as users (x-parameter-scopes); a token without it is forbidden before the request is read. " +
			"A step after the delete committed that fails, such as a refresh of the policy, is logged, and the answer is still what was removed.",
		Tags: []string{"Users"},
	}, needs(scope.Users).withParamScopes("withNodes", scope.DevicesCore), []answer{
		userNotFound,
		onError(
			db.ErrUserStillHasNodes,
			CodeUserHasNodes,
			"The user owns nodes; send withNodes=true to delete them with it.",
		),
		onError(
			state.ErrUserChanged,
			CodeUserChanged,
			"A node or a key of the user came or went since the dry run; run it again.",
		),
	}, func(_ context.Context, in *deleteUserInput) (*struct{ Body DeletedUser }, error) {
		id, err := pathID[types.UserID](in.ID)
		if err != nil {
			return nil, err
		}

		obj := userObject(id, b.userView(id))

		del, changes, err := b.State.DeleteUserIf(
			id,
			in.WithNodes,
			in.DryRun,
			in.Expect,
		)
		b.Change(changes...)

		if hn, ok := errors.AsType[*db.UserHasNodesError](err); ok {
			err = &detailsError{
				err:     err,
				details: map[string]any{"nodes": nodeReferences(hn.Nodes)},
			}
		}

		if err != nil {
			return nil, about(err, obj)
		}

		return &struct{ Body DeletedUser }{Body: DeletedUser{
			Nodes:        nodeReferences(del.Nodes),
			AuthKeyCount: len(del.AuthKeys),
			APIKeyCount:  len(del.APIKeys),
			Expect:       del.Expect,
		}}, nil
	})
}

// nodeReferences names nodes as they are stored, in their order.
func nodeReferences(nodes types.Nodes) []NodeReference {
	refs := make([]NodeReference, len(nodes))
	for i, n := range nodes {
		refs[i] = NodeReference{
			ID:   strconv.FormatUint(uint64(n.ID), 10),
			Name: n.GivenName,
		}
	}

	return refs
}

// set applies a field of a PATCH body that was sent.
func set[T any](dst *T, o Optional[T]) {
	if o.Set {
		*dst = o.Value
	}
}

// userFieldChecks are the checks of a local user's fields beyond their
// schema, with the message of each; a message is ours, never the error's
// text, which can quote the request. Every field is also checked for
// characters that change how a terminal shows it.
var userFieldChecks = map[string]struct {
	check   func(string) error
	message string
}{
	"name": {
		util.ValidateUsername,
		"is not a valid username: at least 2 characters, starting with a letter, of letters, digits, '-', '.', '_' and at most one '@'",
	},
	"displayName": {func(string) error { return nil }, ""},
	"email":       {types.ValidateEmail, "is not one email address"},
	"profilePicUrl": {
		types.ValidateProfilePicURL,
		"is not an absolute http or https URL with a host and no user info",
	},
}

// checkUserFields checks each field the body gives, by its name, and
// returns every one that is not valid, beside the errors of the schema: a
// member of the wrong type stops the typed decode, not the check of its
// siblings.
func checkUserFields(raw []byte, patch bool) []error {
	var members map[string]any

	err := bodyFormat.Unmarshal(raw, &members)
	if err != nil {
		return nil
	}

	var errs []FieldError

	fields := map[string]*string{}

	for _, name := range slices.Sorted(maps.Keys(members)) {
		text, isText := members[name].(string)
		_, known := userFieldChecks[name]

		switch {
		case !known:
			errs = append(
				errs,
				FieldError{Location: "body." + name, Message: "unexpected property"},
			)
		case members[name] == nil && name == "name":
			errs = append(
				errs,
				FieldError{
					Location: "body." + name,
					Message:  "cannot be null; send a valid username",
				},
			)
		case members[name] == nil:
			errs = append(
				errs,
				FieldError{
					Location: "body." + name,
					Message:  nullMessage(reflect.TypeFor[Optional[string]](), patch),
				},
			)
		case isText:
			fields[name] = &text
		}
	}

	for _, name := range slices.Sorted(maps.Keys(fields)) {
		c := userFieldChecks[name]

		switch {
		case types.ValidateUserText(*fields[name]) != nil:
			errs = append(
				errs,
				FieldError{Location: "body." + name, Message: hasControlCharacter},
			)
		case c.check(*fields[name]) != nil:
			errs = append(
				errs,
				FieldError{Location: "body." + name, Message: c.message},
			)
		}
	}

	out := make([]error, len(errs))
	for i, e := range errs {
		out[i] = &huma.ErrorDetail{Location: e.Location, Message: e.Message, Value: e}
	}

	return out
}

// takenBy is err with the text that is taken, as sent, in details: the
// object's name is the holder's login name, which need not be that text.
// When a check of the texts of a user refused it, the holder is the object.
func takenBy(err error, name, email string) error {
	switch {
	case errors.Is(err, db.ErrUserEmailTaken):
		err = &detailsError{err: err, details: map[string]any{"email": email}}
	case errors.Is(err, db.ErrUserNameTaken), errors.Is(err, gorm.ErrDuplicatedKey):
		err = &detailsError{err: err, details: map[string]any{"name": name}}
	default:
		return err
	}

	if te, ok := errors.AsType[*db.UserTakenError](err); ok {
		return about(err, userObject(types.UserID(te.Holder.ID), te.Holder.View()))
	}

	return err
}

// userView is the user with id, or an invalid view when it cannot be read.
func (b Backend) userView(id types.UserID) types.UserView {
	u, err := b.State.GetUserByID(id)
	if err != nil {
		return types.UserView{}
	}

	return u.View()
}

// userObject is the object of a problem about the user with id; its name is
// empty when u is not valid.
func userObject(id types.UserID, u types.UserView) ProblemObject {
	return ProblemObject{
		Kind: "user",
		ID:   strconv.FormatUint(uint64(id), 10),
		Name: u.Username(),
	}
}

// user is u with the nodes it owns now.
func (b Backend) user(u types.UserView) User {
	id := types.UserID(u.ID())

	return userFromView(u, b.State.ListNodesByUsers([]types.UserID{id})[id])
}

// userFromView is u with owned, the nodes it owns in one snapshot.
func userFromView(u types.UserView, owned views.Slice[types.NodeView]) User {
	sorted := owned.AsSlice()
	slices.SortFunc(
		sorted,
		func(a, b types.NodeView) int { return cmp.Compare(a.ID(), b.ID()) },
	)
	nodes := make([]NodeReference, len(sorted))

	for i, n := range sorted {
		nodes[i] = NodeReference{
			ID:   strconv.FormatUint(uint64(n.ID()), 10),
			Name: n.GivenName(),
		}
	}

	provider := "local"
	if u.FromIdentityProvider() {
		provider = "oidc"
	}

	return User{
		ID:            strconv.FormatUint(uint64(u.ID()), 10),
		Name:          u.Name(),
		LoginName:     u.Username(),
		DisplayName:   u.DisplayName(),
		Email:         u.Email(),
		ProfilePicURL: u.ProfilePicURL(),
		Provider:      provider,
		ProviderID:    u.ProviderIdentifier().String,
		NodeCount:     len(nodes),
		Nodes:         nodes,
		Created:       micro(u.CreatedAt()),
	}
}
