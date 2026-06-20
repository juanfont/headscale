package apiv2

import (
	"math"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

// emptyIfNil ensures a slice serializes as [] rather than null, which the
// Tailscale clients expect for empty list fields.
func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}

	return s
}

// parseID parses a decimal entity id from a path segment. A non-numeric id is
// simply an unknown entity, surfaced as a 404 naming subject (e.g. "auth key"),
// so the Tailscale SDK's IsNotFound behaves.
func parseID(rawID, subject string) (uint64, error) {
	id, err := strconv.ParseUint(rawID, util.Base10, util.BitSize64)
	if err != nil {
		return 0, huma.Error404NotFound(subject + " not found")
	}

	return id, nil
}

// parseNodeID parses a device id path segment into a [types.NodeID].
func parseNodeID(rawID string) (types.NodeID, error) {
	id, err := parseID(rawID, "device")
	if err != nil {
		return 0, err
	}

	return types.NodeID(id), nil
}

// timeOrZero dereferences a time pointer, returning the zero time for nil.
func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}

	return *t
}

// expirySeconds reports the lifetime between created and expires in whole
// seconds, the unit the Tailscale spec documents for the response field. The
// lifetime is rounded because the stored expiration is stamped a hair before
// CreatedAt, so an 86400s request would otherwise read back as 86399.
func expirySeconds(created, expires *time.Time) int64 {
	if created == nil || expires == nil {
		return 0
	}

	secs := int64(math.Round(expires.Sub(*created).Seconds()))
	if secs < 0 {
		return 0
	}

	return secs
}
