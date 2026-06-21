package apiv2

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

func init() {
	registrations = append(registrations, registerKeys)
}

// defaultExpiry is the auth-key lifetime when the request omits expirySeconds:
// 90 days, matching Tailscale and the Terraform provider default.
const defaultExpiry = 90 * 24 * time.Hour

const (
	// keyTypeAuth is a machine auth key (Headscale pre-auth key); the default.
	keyTypeAuth = "auth"
	// keyTypeClient is an OAuth client (client-credentials). Multiplexed onto the
	// keys resource exactly as Tailscale does.
	keyTypeClient = "client"
)

// KeyCapabilities maps a resource to the actions a key permits. Headscale
// populates only devices.create (auth keys); the named types (vs Tailscale's
// anonymous nesting) give Huma stable schema names.
type KeyCapabilities struct {
	Devices KeyDeviceCapabilities `json:"devices"`
}

type KeyDeviceCapabilities struct {
	Create KeyDeviceCreateCapabilities `json:"create"`
}

type KeyDeviceCreateCapabilities struct {
	Reusable      bool `json:"reusable"`
	Ephemeral     bool `json:"ephemeral"`
	Preauthorized bool `json:"preauthorized"`
	// Tags is not nullable:"false": the Tailscale clients send "tags":null for
	// an untagged key, which must be accepted. The response always emits [] via
	// emptyIfNil.
	Tags []string `json:"tags"`
}

// CreateKeyRequest is the POST body. It is multiplexed by keyType: "auth"
// (default) creates a machine auth key from Capabilities; "client" creates an
// OAuth client from the top-level Scopes and Tags. expirySeconds is plain
// seconds (unlike the response, see Key).
type CreateKeyRequest struct {
	KeyType string `doc:"Key kind: \"auth\" (default) or \"client\" (OAuth client)." json:"keyType,omitempty"`
	// Capabilities is optional: an auth key carries device-create capabilities,
	// but an OAuth client (keyType:"client") has none and the Tailscale clients
	// omit the field entirely, so it must not be required.
	Capabilities  *KeyCapabilities `json:"capabilities,omitempty"`
	ExpirySeconds int64            `doc:"Lifetime in seconds; defaults to 90 days. Auth keys only." json:"expirySeconds,omitempty"`
	Description   string           `json:"description,omitempty"                                    maxLength:"50"`
	// Scopes and Tags are top-level and apply only to keyType "client" (an OAuth
	// client). Auth-key tags live under Capabilities.Devices.Create.Tags.
	Scopes []string `doc:"OAuth scopes granted to the client. keyType=client only." json:"scopes,omitempty"`
	Tags   []string `doc:"Tags the client may assign. keyType=client only."         json:"tags,omitempty"`
}

// Key is the Tailscale key response, shared by auth keys and OAuth clients.
// expirySeconds is emitted in seconds to match the Tailscale spec; the secret
// key is present only at creation.
type Key struct {
	ID            string          `json:"id"`
	KeyType       string          `json:"keyType"`
	Key           string          `json:"key,omitempty"`
	Description   string          `json:"description,omitempty"`
	ExpirySeconds int64           `json:"expirySeconds,omitempty"`
	Created       time.Time       `json:"created"`
	Expires       *time.Time      `json:"expires,omitempty"`
	Revoked       *time.Time      `json:"revoked,omitempty"`
	Invalid       bool            `json:"invalid"`
	Capabilities  KeyCapabilities `json:"capabilities"`
	Scopes        []string        `json:"scopes,omitempty"`
	Tags          []string        `json:"tags,omitempty"`
	UserID        string          `json:"userId,omitempty"`
}

type (
	createKeyInput struct {
		Tailnet string `doc:"Tailnet; must be \"-\" (the single Headscale tailnet)." path:"tailnet"`
		Body    CreateKeyRequest
	}

	listKeysInput struct {
		Tailnet string `path:"tailnet"`
		All     bool   `doc:"Accepted for compatibility; Headscale returns all keys." query:"all"`
	}

	keyByIDInput struct {
		Tailnet string `path:"tailnet"`
		KeyID   string `path:"keyId"`
	}

	keyOutput struct {
		Body Key
	}

	listKeysOutput struct {
		Body struct {
			Keys []Key `json:"keys" nullable:"false"`
		}
	}

	deleteKeyOutput struct {
		Body struct{}
	}
)

// The keys resource is multiplexed by keyType (auth key vs OAuth client), so the
// scope an operation requires depends on the request rather than being fixed.
// requireScope (which the middleware enforces statically) is therefore omitted
// here; each handler authorizes via requireKeyScope once the kind is known.
func registerKeys(api huma.API, b Backend) {
	keysTags := []string{"Keys", "Tailscale compat"}

	huma.Register(api, huma.Operation{
		OperationID: "createKey",
		Method:      http.MethodPost,
		Path:        "/api/v2/tailnet/{tailnet}/keys",
		Summary:     "Create an auth key or OAuth client",
		Description: "Requires the `auth_keys` scope for an auth key, or `oauth_keys` for an OAuth client (an admin API key is all-access).",
		Tags:        keysTags,
		Security:    security,
		Errors: []int{
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, func(ctx context.Context, in *createKeyInput) (*keyOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		if in.Body.KeyType == keyTypeClient {
			return createOAuthClient(ctx, b, in.Body)
		}

		return createAuthKey(ctx, b, in.Body)
	})

	huma.Register(api, huma.Operation{
		OperationID: "listKeys",
		Method:      http.MethodGet,
		Path:        "/api/v2/tailnet/{tailnet}/keys",
		Summary:     "List auth keys and OAuth clients",
		Description: "A token sees the kinds it can read: `auth_keys:read` for auth keys, `oauth_keys:read` for OAuth clients (an admin API key sees all).",
		Tags:        keysTags,
		Security:    security,
		Errors: []int{
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, func(ctx context.Context, in *listKeysInput) (*listKeysOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		scopes, isOAuth := principalScopes(ctx)

		out := &listKeysOutput{}
		out.Body.Keys = []Key{}

		// A token sees the key kinds it has read scope for; an admin key sees all.
		if !isOAuth || scope.Grants(scope.Parse(scopes), scope.AuthKeysRead) {
			keys, err := b.State.ListPreAuthKeys()
			if err != nil {
				return nil, huma.Error500InternalServerError("listing auth keys", err)
			}

			for i := range keys {
				out.Body.Keys = append(out.Body.Keys, keyFromStored(&keys[i]))
			}
		}

		if !isOAuth || scope.Grants(scope.Parse(scopes), scope.OAuthKeysRead) {
			clients, err := b.State.ListOAuthClients()
			if err != nil {
				return nil, huma.Error500InternalServerError("listing oauth clients", err)
			}

			for i := range clients {
				out.Body.Keys = append(out.Body.Keys, oauthClientToKey(&clients[i], ""))
			}
		}

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "getKey",
		Method:      http.MethodGet,
		Path:        "/api/v2/tailnet/{tailnet}/keys/{keyId}",
		Summary:     "Get an auth key or OAuth client",
		Description: "Requires `auth_keys:read` for an auth key, or `oauth_keys:read` for an OAuth client (an admin API key is all-access).",
		Tags:        keysTags,
		Security:    security,
		Errors: []int{
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, func(ctx context.Context, in *keyByIDInput) (*keyOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		// An OAuth client id is a hex string distinct from a numeric auth-key id,
		// so a client lookup that hits is authoritative; otherwise fall through to
		// the auth-key path. The lookup is gated on the caller actually holding
		// oauth_keys:read so a token without it cannot tell a real client id (403)
		// from an unknown key (404) — i.e. no client-existence oracle.
		if requireKeyScope(ctx, scope.OAuthKeysRead) == nil {
			client, err := b.State.GetOAuthClientByClientID(in.KeyID)
			if err == nil {
				return &keyOutput{Body: oauthClientToKey(client, "")}, nil
			}
		}

		err = requireKeyScope(ctx, scope.AuthKeysRead)
		if err != nil {
			return nil, err
		}

		key, err := findKeyByID(b, in.KeyID)
		if err != nil {
			return nil, err
		}

		return &keyOutput{Body: keyFromStored(key)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "deleteKey",
		Method:        http.MethodDelete,
		Path:          "/api/v2/tailnet/{tailnet}/keys/{keyId}",
		Summary:       "Delete an auth key or OAuth client",
		Description:   "Requires the `auth_keys` scope for an auth key, or `oauth_keys` for an OAuth client (an admin API key is all-access).",
		Tags:          keysTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors: []int{
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, func(ctx context.Context, in *keyByIDInput) (*deleteKeyOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		// Gated on oauth_keys (write) for the same no-existence-oracle reason as
		// getKey: a token without it must not learn that an id is an OAuth client.
		if requireKeyScope(ctx, scope.OAuthKeys) == nil {
			_, err = b.State.GetOAuthClientByClientID(in.KeyID)
			if err == nil {
				err = b.State.RevokeOAuthClient(in.KeyID)
				if err != nil {
					return nil, mapError("deleting oauth client", err)
				}

				return &deleteKeyOutput{}, nil
			}
		}

		err = requireKeyScope(ctx, scope.AuthKeys)
		if err != nil {
			return nil, err
		}

		id, err := parseID(in.KeyID, "auth key")
		if err != nil {
			return nil, err
		}

		// Tailscale's DELETE revokes the key but keeps it retrievable (invalid)
		// rather than destroying it; the collector reaps it after the retention
		// window.
		err = b.State.RevokePreAuthKey(id)
		if err != nil {
			return nil, mapError("revoking auth key", err)
		}

		return &deleteKeyOutput{}, nil
	})
}

// requireKeyScope authorizes a keys operation for an OAuth access token. An admin
// API key carries no OAuth scopes and is all-access, so it always passes.
func requireKeyScope(ctx context.Context, need scope.Scope) error {
	scopes, isOAuth := principalScopes(ctx)
	if !isOAuth {
		return nil
	}

	if !scope.Grants(scope.Parse(scopes), need) {
		return huma.Error403Forbidden("token is missing the required scope " + string(need))
	}

	return nil
}

// createAuthKey creates a machine auth key (pre-auth key). Ownership: tags -> a
// tagged key; no tags -> owned by the API key's user. An OAuth access token must
// mint tagged keys, and each tag must be within the token's grant.
func createAuthKey(ctx context.Context, b Backend, body CreateKeyRequest) (*keyOutput, error) {
	err := requireKeyScope(ctx, scope.AuthKeys)
	if err != nil {
		return nil, err
	}

	var create KeyDeviceCreateCapabilities
	if body.Capabilities != nil {
		create = body.Capabilities.Devices.Create
	}

	tokenTags, isOAuth := principalTags(ctx)

	var userID *types.UserID

	switch {
	case len(create.Tags) > 0:
		// A key minted by an OAuth token may only carry tags within the token's
		// grant (held directly, or owned by a held tag) and defined in policy,
		// matching SetNodeTags. An admin key keeps the historical behaviour of
		// validating only tag syntax (db.validateACLTags).
		if isOAuth {
			for _, tag := range create.Tags {
				if !b.State.TagExists(tag) {
					return nil, huma.Error400BadRequest("tag " + tag + " is not defined in policy")
				}

				if !b.State.TagOwnedByTags(tag, tokenTags) {
					return nil, huma.Error403Forbidden(
						"token may not assign tag " + tag,
					)
				}
			}
		}

	case isOAuth:
		// OAuth-minted keys are tailnet/tag-owned; an untagged (user-owned) key
		// cannot be created from a token.
		return nil, huma.Error403Forbidden("an OAuth client must create tagged auth keys")

	default:
		uid, ok := ownerUser(ctx)
		if !ok {
			return nil, huma.Error400BadRequest(
				"an auth key without tags must be created with a user-owned API key",
			)
		}

		userID = &uid
	}

	expiration := time.Now().Add(expiryDuration(body.ExpirySeconds))

	pak, err := b.State.CreatePreAuthKey(
		userID,
		create.Reusable,
		create.Ephemeral,
		&expiration,
		create.Tags,
	)
	if err != nil {
		return nil, mapError("creating auth key", err)
	}

	if body.Description != "" {
		err := b.State.SetPreAuthKeyDescription(pak.ID, body.Description)
		if err != nil {
			return nil, huma.Error500InternalServerError("setting auth key description", err)
		}
	}

	return &keyOutput{Body: keyFromNew(pak, body)}, nil
}

// createOAuthClient creates an OAuth client (keyType:"client"). The client secret
// is returned once, here.
func createOAuthClient(ctx context.Context, b Backend, body CreateKeyRequest) (*keyOutput, error) {
	err := requireKeyScope(ctx, scope.OAuthKeys)
	if err != nil {
		return nil, err
	}

	if len(body.Scopes) == 0 {
		return nil, huma.Error400BadRequest("an OAuth client must declare at least one scope")
	}

	// Tailscale: tags are mandatory when the scopes include devices:core or
	// auth_keys, because such a client mints tagged, tailnet-owned credentials.
	if scope.RequiresTags(scope.Parse(body.Scopes)) && len(body.Tags) == 0 {
		return nil, huma.Error400BadRequest(
			"tags are required when scopes include devices:core or auth_keys",
		)
	}

	// A client created by an OAuth token may not be granted authority the token
	// lacks: its scopes must each be within the token's grant, and its tags within
	// the token's tags and defined in policy (matching SetNodeTags). Otherwise an
	// oauth_keys token could mint an all-access client and escalate. An admin API
	// key (not an OAuth token) is unrestricted and keeps the historical tag
	// behaviour (syntax-only validation).
	if tokenScopes, isOAuth := principalScopes(ctx); isOAuth {
		for _, s := range body.Scopes {
			if !scope.Grants(scope.Parse(tokenScopes), scope.Scope(s)) {
				return nil, huma.Error403Forbidden(
					"client may not be granted scope " + s + " beyond the creating token",
				)
			}
		}

		tokenTags, _ := principalTags(ctx)

		for _, tag := range body.Tags {
			if !b.State.TagExists(tag) {
				return nil, huma.Error400BadRequest("tag " + tag + " is not defined in policy")
			}

			if !b.State.TagOwnedByTags(tag, tokenTags) {
				return nil, huma.Error403Forbidden(
					"client may not be granted tag " + tag + " beyond the creating token",
				)
			}
		}
	}

	var creator *uint

	if uid, ok := ownerUser(ctx); ok {
		u := uint(uid)
		creator = &u
	}

	secret, client, err := b.State.CreateOAuthClient(body.Scopes, body.Tags, body.Description, creator)
	if err != nil {
		return nil, mapError("creating oauth client", err)
	}

	return &keyOutput{Body: oauthClientToKey(client, secret)}, nil
}

// findKeyByID looks up a stored pre-auth key by its (stringified) id with a
// direct by-id query; an unknown id surfaces as gorm.ErrRecordNotFound, which
// mapError turns into a 404.
func findKeyByID(b Backend, rawID string) (*types.PreAuthKey, error) {
	id, err := parseID(rawID, "auth key")
	if err != nil {
		return nil, err
	}

	pak, err := b.State.GetPreAuthKeyByID(id)
	if err != nil {
		return nil, mapError("looking up auth key", err)
	}

	return pak, nil
}

// keyFromNew builds the create response from the freshly created key. The
// plaintext secret is returned only here. preauthorized is reported true to
// match keyFromStored: Headscale always authorizes pre-auth-key nodes, so the
// create and read paths must agree or the Terraform provider sees a diff.
func keyFromNew(pak *types.PreAuthKeyNew, req CreateKeyRequest) Key {
	var create KeyDeviceCreateCapabilities
	if req.Capabilities != nil {
		create = req.Capabilities.Devices.Create
	}

	key := Key{
		ID:          pak.StringID(),
		KeyType:     keyTypeAuth,
		Key:         pak.Key,
		Description: req.Description,
		Created:     timeOrZero(pak.CreatedAt),
		Capabilities: capabilities(
			create.Reusable,
			create.Ephemeral,
			true,
			pak.Tags,
		),
		Tags: pak.Tags,
	}

	if pak.Expiration != nil {
		key.Expires = pak.Expiration
		key.ExpirySeconds = expirySeconds(pak.CreatedAt, pak.Expiration)
	}

	// A tagged key presents no owner; a user-owned key reports its user id.
	if len(pak.Tags) == 0 && pak.User != nil {
		key.UserID = pak.User.StringID()
	}

	return key
}

// keyFromStored builds the get/list response from a stored key. The secret is
// never returned here. preauthorized is reported true: Headscale has no separate
// device-approval step, so every pre-auth key authorizes its nodes. Reporting it
// stably keeps the Terraform provider from seeing a forced-replacement diff.
func keyFromStored(pak *types.PreAuthKey) Key {
	key := Key{
		ID:           pak.StringID(),
		KeyType:      keyTypeAuth,
		Description:  pak.Description,
		Created:      timeOrZero(pak.CreatedAt),
		Invalid:      pak.Validate() != nil,
		Capabilities: capabilities(pak.Reusable, pak.Ephemeral, true, pak.Tags),
		Tags:         pak.Tags,
	}

	if pak.Expiration != nil {
		key.Expires = pak.Expiration
		key.ExpirySeconds = expirySeconds(pak.CreatedAt, pak.Expiration)
	}

	if pak.Revoked != nil {
		key.Revoked = pak.Revoked
	}

	if len(pak.Tags) == 0 && pak.User != nil {
		key.UserID = pak.User.StringID()
	}

	return key
}

// oauthClientToKey builds the keys response for an OAuth client. secret is the
// plaintext client secret, set only on the create response and empty on get/list
// (the secret is never re-exposed).
func oauthClientToKey(client *types.OAuthClient, secret string) Key {
	key := Key{
		ID:          client.ClientID,
		KeyType:     keyTypeClient,
		Key:         secret,
		Description: client.Description,
		Created:     timeOrZero(client.CreatedAt),
		Scopes:      emptyIfNil(client.Scopes),
		Tags:        emptyIfNil(client.Tags),
	}

	if client.Revoked != nil {
		key.Revoked = client.Revoked
		key.Invalid = true
	}

	if client.UserID != nil {
		key.UserID = strconv.FormatUint(uint64(*client.UserID), util.Base10)
	}

	return key
}

func capabilities(
	reusable, ephemeral, preauthorized bool,
	tags []string,
) KeyCapabilities {
	return KeyCapabilities{
		Devices: KeyDeviceCapabilities{Create: KeyDeviceCreateCapabilities{
			Reusable:      reusable,
			Ephemeral:     ephemeral,
			Preauthorized: preauthorized,
			Tags:          emptyIfNil(tags),
		}},
	}
}

func expiryDuration(seconds int64) time.Duration {
	if seconds <= 0 {
		return defaultExpiry
	}

	return time.Duration(seconds) * time.Second
}
