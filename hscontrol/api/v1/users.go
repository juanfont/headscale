package apiv1

import (
	"cmp"
	"context"
	"slices"

	oas "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// CreateUser creates a user and distributes the resulting policy change.
func (s *Server) CreateUser(
	_ context.Context,
	req *oas.CreateUserReq,
) (*oas.CreateUserOK, error) {
	newUser := types.User{
		Name:          req.Name.Or(""),
		DisplayName:   req.DisplayName.Or(""),
		Email:         req.Email.Or(""),
		ProfilePicURL: req.PictureUrl.Or(""),
	}

	user, policyChanged, err := s.state.CreateUser(newUser)
	if err != nil {
		return nil, internalError("creating user: " + err.Error())
	}

	s.change(policyChanged)

	return &oas.CreateUserOK{User: oas.NewOptUser(oasUser(user.View()))}, nil
}

// ListUsers lists users, optionally filtered by id, name, or email, sorted by id.
func (s *Server) ListUsers(
	_ context.Context,
	params oas.ListUsersParams,
) (*oas.ListUsersOK, error) {
	var (
		users []types.User
		err   error
	)

	switch {
	case params.Name.Or("") != "":
		users, err = s.state.ListUsersWithFilter(&types.User{Name: params.Name.Or("")})
	case params.Email.Or("") != "":
		users, err = s.state.ListUsersWithFilter(&types.User{Email: params.Email.Or("")})
	case params.ID.Or(0) != 0:
		users, err = s.state.ListUsersWithFilter(
			&types.User{Model: gorm.Model{ID: uint(params.ID.Or(0))}},
		)
	default:
		users, err = s.state.ListAllUsers()
	}

	if err != nil {
		return nil, mapStateError(err)
	}

	slices.SortFunc(users, func(a, b types.User) int { return cmp.Compare(a.ID, b.ID) })

	out := make([]oas.User, len(users))
	for i := range users {
		out[i] = oasUser(users[i].View())
	}

	return &oas.ListUsersOK{Users: out}, nil
}

// RenameUser renames a user and distributes the resulting policy change.
func (s *Server) RenameUser(
	_ context.Context,
	params oas.RenameUserParams,
) (*oas.RenameUserOK, error) {
	oldUser, err := s.state.GetUserByID(types.UserID(params.OldID))
	if err != nil {
		return nil, mapStateError(err)
	}

	_, c, err := s.state.RenameUser(types.UserID(oldUser.ID), params.NewName)
	if err != nil {
		return nil, mapStateError(err)
	}

	s.change(c)

	newUser, err := s.state.GetUserByName(params.NewName)
	if err != nil {
		return nil, mapStateError(err)
	}

	return &oas.RenameUserOK{User: oas.NewOptUser(oasUser(newUser.View()))}, nil
}

// DeleteUser deletes a user and distributes the resulting policy change.
func (s *Server) DeleteUser(_ context.Context, params oas.DeleteUserParams) error {
	user, err := s.state.GetUserByID(types.UserID(params.ID))
	if err != nil {
		return mapStateError(err)
	}

	policyChanged, err := s.state.DeleteUser(types.UserID(user.ID))
	if err != nil {
		return mapStateError(err)
	}

	s.change(policyChanged)

	return nil
}
