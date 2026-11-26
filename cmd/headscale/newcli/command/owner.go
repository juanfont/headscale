package command

import (
	"strings"

	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
)

// Owned is an owner as a question or a sentence about its object says it:
// "owned by User 3 (alice)", "tagged tag:ci, tag:build", or "with no
// owner".
func Owned(o nullable.Nullable[clientv0.Owner]) string {
	name, tagged := OwnerName(o)

	switch {
	case name == "":
		return "with no owner"
	case tagged:
		return "tagged " + name
	}

	return "owned by " + name
}

// OwnerName is the owner itself, as messages name it, and whether it is
// tags: "User 3 (alice)", or
// the tags, "tag:ci, tag:build"; "" for no owner.
func OwnerName(o nullable.Nullable[clientv0.Owner]) (string, bool) {
	owner, err := o.Get()
	if err != nil {
		return "", false
	}

	u, err := owner.User.Get()
	if err == nil {
		return table.Entity("user", u.Id, u.LoginName), false
	}

	tags := make([]string, 0, len(owner.Tags))
	for _, t := range owner.Tags {
		tags = append(tags, table.Visible(t, ""))
	}

	return strings.Join(tags, ", "), true
}
