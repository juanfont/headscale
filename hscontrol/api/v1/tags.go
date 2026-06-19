package apiv1

import (
	"errors"
	"strings"
)

// ACL tag validation, shared by the node and pre-auth-key resources. These
// reproduce the gRPC validateTag checks and messages.
var (
	errTagMissingPrefix = errors.New("tag must start with the string 'tag:'")
	errTagNotLowercase  = errors.New("tag should be lowercase")
	errTagHasSpaces     = errors.New("tags must not contain spaces")
)

// validateTag reports whether an ACL tag is well formed: it must start with
// "tag:", be lowercase, and contain no spaces.
func validateTag(tag string) error {
	switch {
	case !strings.HasPrefix(tag, "tag:"):
		return errTagMissingPrefix
	case strings.ToLower(tag) != tag:
		return errTagNotLowercase
	case len(strings.Fields(tag)) > 1:
		return errTagHasSpaces
	default:
		return nil
	}
}
