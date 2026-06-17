package apiv1

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	oas "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
)

// CreatePreAuthKey creates a pre-auth key for a user.
func (s *Server) CreatePreAuthKey(
	_ context.Context,
	req *oas.CreatePreAuthKeyReq,
) (*oas.CreatePreAuthKeyOK, error) {
	var expiration time.Time
	if v, ok := req.Expiration.Get(); ok {
		expiration = v
	}

	for _, tag := range req.AclTags {
		err := validateTag(tag)
		if err != nil {
			return nil, badRequest(err.Error())
		}
	}

	var userID *types.UserID

	if req.User.Or(0) != 0 {
		user, err := s.state.GetUserByID(types.UserID(req.User.Or(0)))
		if err != nil {
			return nil, mapStateError(err)
		}

		userID = user.TypedID()
	}

	preAuthKey, err := s.state.CreatePreAuthKey(
		userID,
		req.Reusable.Or(false),
		req.Ephemeral.Or(false),
		&expiration,
		req.AclTags,
	)
	if err != nil {
		return nil, mapStateError(err)
	}

	return &oas.CreatePreAuthKeyOK{
		PreAuthKey: oas.NewOptPreAuthKey(oasPreAuthKeyNew(preAuthKey)),
	}, nil
}

// ListPreAuthKeys lists all pre-auth keys, sorted by id.
func (s *Server) ListPreAuthKeys(_ context.Context) (*oas.ListPreAuthKeysOK, error) {
	keys, err := s.state.ListPreAuthKeys()
	if err != nil {
		return nil, mapStateError(err)
	}

	slices.SortFunc(keys, func(a, b types.PreAuthKey) int { return cmp.Compare(a.ID, b.ID) })

	out := make([]oas.PreAuthKey, len(keys))
	for i := range keys {
		out[i] = oasPreAuthKey(keys[i].View())
	}

	return &oas.ListPreAuthKeysOK{PreAuthKeys: out}, nil
}

// ExpirePreAuthKey expires a pre-auth key.
func (s *Server) ExpirePreAuthKey(_ context.Context, req *oas.ExpirePreAuthKeyReq) error {
	err := s.state.ExpirePreAuthKey(req.ID.Or(0))
	if err != nil {
		return mapStateError(err)
	}

	return nil
}

// DeletePreAuthKey deletes a pre-auth key.
func (s *Server) DeletePreAuthKey(_ context.Context, params oas.DeletePreAuthKeyParams) error {
	err := s.state.DeletePreAuthKey(params.ID.Or(0))
	if err != nil {
		return mapStateError(err)
	}

	return nil
}

var (
	errTagPrefix    = errors.New("tag must start with the string 'tag:'")
	errTagLowercase = errors.New("tag should be lowercase")
	errTagSpaces    = errors.New("tags must not contain spaces")
)

// validateTag enforces the ACL tag format ("tag:" prefix, lowercase, no spaces).
func validateTag(tag string) error {
	if !strings.HasPrefix(tag, "tag:") {
		return errTagPrefix
	}

	if strings.ToLower(tag) != tag {
		return errTagLowercase
	}

	if len(strings.Fields(tag)) > 1 {
		return errTagSpaces
	}

	return nil
}
