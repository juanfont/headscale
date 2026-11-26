package command

import (
	"context"
	"strconv"
	"strings"

	lib "github.com/juanfont/headscale/cmdline/command"
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

// Owner is the owner of a new key, one argument: a user, looked up as a
// target is, or tags, comma separated, each starting with tag:.
type Owner struct {
	user clientv0.User
	tags []string
}

// User is the user that owns the key; false for tags.
func (o Owner) User() (clientv0.User, bool) { return o.user, o.user.Id != "" }

// Tags are the tags that own the key; none for a user.
func (o Owner) Tags() []string { return o.tags }

// findOwner reads an owner: its form needs no call, a user is looked up.
func findOwner(ctx context.Context, word string) (Owner, error) {
	var tags, users []string

	// Space around an item is dropped, as in every list.
	items := strings.Split(word, ",")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}

	for _, w := range items {
		switch {
		case w == "" && len(items) == 1:
			return Owner{}, lib.EmptyWord("owner")
		case w == "":
			return Owner{}, &lib.LookupError{Text: "the owner list has an empty item."}
		case strings.HasPrefix(w, "tag:"):
			// A tag is sent as it is typed, so it is held to the rule on
			// the way in; a user is only looked up.
			cr := credentials()

			err := cr.Check("<owner>", w)
			if err != nil {
				return Owner{}, err
			}

			tags = append(tags, w)
		default:
			users = append(users, table.Visible(w, ""))
		}
	}

	switch {
	case len(users) > 0 && len(tags) > 0:
		return Owner{}, &lib.LookupError{
			Text: "a key needs one owner: one user, or tags, not both.",
		}
	case len(users) > 1:
		return Owner{}, &lib.LookupError{
			Text: "a key is owned by one user. Got " + strconv.Itoa(
				len(users),
			) + ": " + strings.Join(
				users,
				", ",
			) + ".",
		}
	case len(tags) > 0:
		return Owner{tags: tags}, nil
	}

	u, err := findUser(ctx, items[0])

	return Owner{user: u}, err
}
