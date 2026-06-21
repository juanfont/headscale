package apiv2

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
)

func init() {
	registrations = append(registrations, registerUsers)
}

// Headscale models none of type/role/status and has a single tailnet, so these
// fields are fixed strings. Every account is an active member.
const (
	userTypeMember   = "member"
	userRoleMember   = "member"
	userStatusActive = "active"
	singleTailnetID  = "1"

	// tagTailscaleCompat marks operations ported from the Tailscale API.
	tagTailscaleCompat = "Tailscale compat"
)

// User is the Tailscale user response. Identity fields map from the Headscale
// user; type/role/status/tailnetId are constants (see above); the device fields
// are aggregated from the user's nodes.
type User struct {
	ID                 string    `json:"id"`
	DisplayName        string    `json:"displayName"`
	LoginName          string    `json:"loginName"`
	ProfilePicURL      string    `json:"profilePicUrl"`
	TailnetID          string    `json:"tailnetId"`
	Created            time.Time `json:"created"`
	Type               string    `json:"type"`
	Role               string    `json:"role"`
	Status             string    `json:"status"`
	DeviceCount        int       `json:"deviceCount"`
	LastSeen           time.Time `json:"lastSeen"`
	CurrentlyConnected bool      `json:"currentlyConnected"`
}

type (
	userByIDInput struct {
		UserID string `doc:"User id (the decimal user id)." path:"id"`
	}
	listUsersInput struct {
		Tailnet string `doc:"Tailnet; must be \"-\" (the single Headscale tailnet)."   path:"tailnet"`
		Type    string `doc:"Filter by user type; Headscale users are all \"member\"." query:"type"`
		Role    string `doc:"Filter by user role; Headscale users are all \"member\"." query:"role"`
	}

	userOutput      struct{ Body User }
	listUsersOutput struct {
		Body struct {
			Users []User `json:"users" nullable:"false"`
		}
	}
)

func registerUsers(api huma.API, b Backend) {
	usersTags := []string{"Users", tagTailscaleCompat}

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "getUser",
		Method:      http.MethodGet,
		Path:        "/api/v2/users/{id}",
		Summary:     "Get a user",
		Tags:        usersTags,
		Security:    security,
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.UsersRead), func(ctx context.Context, in *userByIDInput) (*userOutput, error) {
		view, err := lookupUser(b, in.UserID)
		if err != nil {
			return nil, err
		}

		return &userOutput{Body: userFromView(b, view)}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "listUsers",
		Method:      http.MethodGet,
		Path:        "/api/v2/tailnet/{tailnet}/users",
		Summary:     "List users",
		Tags:        usersTags,
		Security:    security,
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.UsersRead), func(ctx context.Context, in *listUsersInput) (*listUsersOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		out := &listUsersOutput{}
		out.Body.Users = []User{}

		// Headscale has only "member" users. A filter for any other type/role
		// matches nothing, so return the empty envelope.
		if !matchesMember(in.Type) || !matchesMember(in.Role) {
			return out, nil
		}

		users, err := b.State.ListAllUsers()
		if err != nil {
			return nil, huma.Error500InternalServerError("listing users", err)
		}

		out.Body.Users = make([]User, 0, len(users))
		for i := range users {
			out.Body.Users = append(out.Body.Users, userFromView(b, users[i].View()))
		}

		return out, nil
	})
}

// lookupUser resolves a user id to its UserView, mapping a malformed or unknown
// id to 404 (the Tailscale SDK keys IsNotFound off the status code), exactly as
// lookupNode does for devices.
func lookupUser(b Backend, rawID string) (types.UserView, error) {
	id, err := parseID(rawID, "user")
	if err != nil {
		return types.UserView{}, err
	}

	user, err := b.State.GetUserByID(types.UserID(id))
	if err != nil {
		return types.UserView{}, mapError("looking up user", err)
	}

	return user.View(), nil
}

// matchesMember reports whether an optional type/role filter selects Headscale's
// only user kind. An empty value means "no filter".
func matchesMember(filter string) bool {
	return filter == "" || filter == userTypeMember
}

// userFromView maps a Headscale user onto the Tailscale User through the
// UserView accessors. deviceCount, lastSeen, and currentlyConnected are
// aggregated from the user's nodes in the NodeStore.
func userFromView(b Backend, view types.UserView) User {
	u := User{
		ID:            strconv.FormatUint(uint64(view.ID()), 10),
		DisplayName:   view.Display(),
		LoginName:     view.Username(),
		ProfilePicURL: view.ProfilePicURL(),
		TailnetID:     singleTailnetID,
		Created:       view.CreatedAt(),
		Type:          userTypeMember,
		Role:          userRoleMember,
		Status:        userStatusActive,
	}

	nodes := b.State.ListNodesByUser(types.UserID(view.ID()))
	u.DeviceCount = nodes.Len()

	for _, node := range nodes.All() {
		if node.IsOnline().Valid() && node.IsOnline().Get() {
			u.CurrentlyConnected = true
		}

		if ls := node.LastSeen(); ls.Valid() && ls.Get().After(u.LastSeen) {
			u.LastSeen = ls.Get()
		}
	}

	return u
}
