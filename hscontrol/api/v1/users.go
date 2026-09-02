package apiv1

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"strconv"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
)

func init() {
	registrations = append(registrations, registerUsers)
}

// CreateUserRequestBody mirrors v1.CreateUserRequest.
type CreateUserRequestBody struct {
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	PictureURL  string `json:"pictureUrl,omitempty"`
}

type (
	createUserInput struct {
		Body CreateUserRequestBody
	}
	userOutput struct {
		Body struct {
			User User `json:"user"`
		}
	}
)

// SetUserRequestBody is a partial update of a user's presentational fields.
//
// A field that is absent from the request body is left unchanged; a field that
// is present is written as given, and an explicit empty string clears it. That
// distinction is why the fields are pointers.
type SetUserRequestBody struct {
	DisplayName *string `doc:"Display name; empty string clears it."        json:"displayName,omitempty"`
	Email       *string `doc:"Email; empty string clears it."               json:"email,omitempty"`
	PictureURL  *string `doc:"Profile picture URL; empty string clears it." json:"pictureUrl,omitempty"`
}

type (
	setUserInput struct {
		ID   string `format:"uint64" path:"id"`
		Body SetUserRequestBody
	}

	renameUserInput struct {
		OldID   string `format:"uint64" path:"oldId"`
		NewName string `path:"newName"`
	}

	deleteUserInput struct {
		ID string `format:"uint64" path:"id"`
	}
	deleteUserOutput struct {
		Body struct{}
	}
)

type (
	listUsersInput struct {
		ID    string `format:"uint64" query:"id"`
		Name  string `query:"name"`
		Email string `query:"email"`
	}
	listUsersOutput struct {
		Body struct {
			Users []User `json:"users" nullable:"false"`
		}
	}
)

func registerUsers(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "createUser",
		Method:      http.MethodPost,
		Path:        "/api/v1/user",
		Summary:     "Create user",
		Tags:        []string{"Users"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *createUserInput) (*userOutput, error) {
		// Pre-check yields a 409 for the common case; the DB unique constraint
		// is the real guard.
		if in.Body.Name != "" {
			_, err := b.State.GetUserByName(in.Body.Name)
			if err == nil {
				return nil, huma.Error409Conflict("user already exists")
			}
		}

		user, policyChanged, err := b.State.CreateUser(types.User{
			Name:          in.Body.Name,
			DisplayName:   in.Body.DisplayName,
			Email:         in.Body.Email,
			ProfilePicURL: in.Body.PictureURL,
		})
		if err != nil {
			return nil, mapError("creating user", err)
		}

		b.Change(policyChanged)

		out := &userOutput{}
		out.Body.User = userFromView(user.View())

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "setUser",
		Method:      http.MethodPut,
		Path:        "/api/v1/user/{id}",
		Summary:     "Set user profile fields",
		Description: "Updates the presentational fields of a user: display name, " +
			"email and profile picture URL. Fields left out of the request body are " +
			"unchanged; a field set to an empty string is cleared. Users provisioned " +
			"by OIDC cannot be edited, as the provider re-applies its claims on every " +
			"login.",
		Tags:     []string{"Users"},
		Security: bearerAuth,
	}, func(ctx context.Context, in *setUserInput) (*userOutput, error) {
		id, err := parseUserID(in.ID)
		if err != nil {
			return nil, err
		}

		user, c, err := b.State.SetUserProfile(id, types.UserProfileUpdate{
			DisplayName:   in.Body.DisplayName,
			Email:         in.Body.Email,
			ProfilePicURL: in.Body.PictureURL,
		})
		if err != nil {
			return nil, mapError("setting user profile", err)
		}

		b.Change(c)

		out := &userOutput{}
		out.Body.User = userFromView(user.View())

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "renameUser",
		Method:      http.MethodPost,
		Path:        "/api/v1/user/{oldId}/rename/{newName}",
		Summary:     "Rename user",
		Tags:        []string{"Users"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *renameUserInput) (*userOutput, error) {
		oldID, err := parseUserID(in.OldID)
		if err != nil {
			return nil, err
		}

		oldUser, err := b.State.GetUserByID(oldID)
		if err != nil {
			return nil, mapError("renaming user", err)
		}

		_, c, err := b.State.RenameUser(types.UserID(oldUser.ID), in.NewName)
		if err != nil {
			return nil, mapError("renaming user", err)
		}

		b.Change(c)

		newUser, err := b.State.GetUserByName(in.NewName)
		if err != nil {
			return nil, huma.Error500InternalServerError("renaming user", err)
		}

		out := &userOutput{}
		out.Body.User = userFromView(newUser.View())

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "deleteUser",
		Method:      http.MethodDelete,
		Path:        "/api/v1/user/{id}",
		Summary:     "Delete user",
		Tags:        []string{"Users"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *deleteUserInput) (*deleteUserOutput, error) {
		id, err := parseUserID(in.ID)
		if err != nil {
			return nil, err
		}

		user, err := b.State.GetUserByID(id)
		if err != nil {
			return nil, mapError("deleting user", err)
		}

		policyChanged, err := b.State.DeleteUser(types.UserID(user.ID))
		if err != nil {
			return nil, mapError("deleting user", err)
		}

		b.Change(policyChanged)

		return &deleteUserOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listUsers",
		Method:      http.MethodGet,
		Path:        "/api/v1/user",
		Summary:     "List users",
		Tags:        []string{"Users"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *listUsersInput) (*listUsersOutput, error) {
		// Gateway parity: a non-numeric id is a 400 even when other filters win.
		if in.ID != "" {
			_, err := strconv.ParseUint(in.ID, 10, 64)
			if err != nil {
				return nil, huma.Error400BadRequest("invalid id", err)
			}
		}

		users, err := listUsersFiltered(b, in)
		if err != nil {
			return nil, huma.Error500InternalServerError("listing users", err)
		}

		// Match the gRPC handler's ascending-ID ordering.
		slices.SortFunc(users, func(a, b types.User) int {
			return cmp.Compare(a.ID, b.ID)
		})

		out := &listUsersOutput{}

		out.Body.Users = make([]User, len(users))
		for i := range users {
			out.Body.Users[i] = userFromView(users[i].View())
		}

		return out, nil
	})
}

// listUsersFiltered reproduces the gRPC ListUsers precedence: name, then email,
// then id, otherwise all users.
func listUsersFiltered(b Backend, in *listUsersInput) ([]types.User, error) {
	switch {
	case in.Name != "":
		return b.State.ListUsersWithFilter(&types.User{Name: in.Name})
	case in.Email != "":
		return b.State.ListUsersWithFilter(&types.User{Email: in.Email})
	case in.ID != "":
		id, err := strconv.ParseUint(in.ID, 10, 64)
		if err != nil {
			return nil, err
		}

		if id == 0 {
			return b.State.ListAllUsers()
		}

		return b.State.ListUsersWithFilter(&types.User{ID: uint(id)})
	default:
		return b.State.ListAllUsers()
	}
}

func parseUserID(s string) (types.UserID, error) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, huma.Error400BadRequest("invalid user id", err)
	}

	return types.UserID(id), nil
}
