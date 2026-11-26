package command

import (
	"testing"
	"time"

	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

// TestEnded: every sentence of the end of a credential, for a credential
// that was valid and for one revoked already.
func TestEnded(t *testing.T) {
	t.Parallel()

	now := time.Date(2999, 1, 10, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) nullable.Nullable[time.Time] { return nullable.NewNullableWithValue(now.Add(d)) }
	day := 24 * time.Hour

	valid := Ended{
		ID:      "2",
		Name:    "API key 2 (tr81ys)",
		Revoked: nullable.NewNullNullable[time.Time](),
	}
	revoked := Ended{ID: "2", Name: "API key 2 (tr81ys)", Revoked: at(-day)}
	read := func(removal nullable.Nullable[time.Time]) Ended {
		return Ended{ID: "2", Revoked: at(0), Removal: removal}
	}

	for _, tt := range []struct {
		name          string
		before, after Ended
		want          string
	}{
		{"removed", valid, read(at(7 * day)), "API key 2 (tr81ys) is revoked. Its record is removed in 7d."},
		{"kept", valid, read(nullable.NewNullNullable[time.Time]()), "API key 2 (tr81ys) is revoked. Its record is kept."},
		{"due", valid, read(at(0)), "API key 2 (tr81ys) is revoked. Its record is due for removal."},
		{"not read", valid, Ended{}, "API key 2 (tr81ys) is revoked."},
		{"revoked already, removed", revoked, read(at(6 * day)), "API key 2 (tr81ys) was revoked already. Its record is removed in 6d."},
		{"revoked already, kept", revoked, read(nullable.NewNullNullable[time.Time]()), "API key 2 (tr81ys) was revoked already. Its record is kept."},
		{"revoked already, due", revoked, read(at(-time.Hour)), "API key 2 (tr81ys) was revoked already. Its record is due for removal."},
		{"revoked already, not read", revoked, Ended{}, "API key 2 (tr81ys) was revoked already."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, ended(tt.before, tt.after, now))
		})
	}
}

// endOf is a delete made by NewEnd, for the checks of the tree.
func endOf() Node {
	return NewEnd(EndSpec[getIn, item]{
		Short:    "S",
		Long:     "S.",
		Example:  []string{"prog keys delete 7"},
		Target:   func(getIn) item { return item{} },
		Of:       func(item) Ended { return Ended{} },
		Revoke:   func(Ctx, string) error { return nil },
		Get:      func(Ctx, string) (item, error) { return item{}, nil },
		NeverOwn: true,
	})
}

// TestEndOnly: the tree ties a credential's pieces to each other. A delete
// whose target has revoked, or that stands beside a Secret, is made by
// NewEnd, whatever its target; NewEnd stands only beside a Secret; and it
// says whether the CLI can call with the credential.
func TestEndOnly(t *testing.T) {
	t.Parallel()

	type cred struct {
		ID      string                       `json:"id"`
		Revoked nullable.Nullable[time.Time] `json:"revoked"`
	}

	type in struct {
		Cred cred `arg:"cred"`
	}

	type secreted struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}

	byHand := New(Spec[in, NoOutput]{
		Name:    "delete",
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog creds delete 2"},
		Local:   true,
		Confirm: func(Ctx, in) (Prompt, error) { return Prompt{}, nil },
		Run:     noop[in, NoOutput],
	})
	plain := New(Spec[getIn, NoOutput]{
		Name:    "delete",
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog keys delete 7"},
		Local:   true,
		Run:     noop[getIn, NoOutput],
		Confirm: func(Ctx, getIn) (Prompt, error) { return Prompt{}, nil },
	})
	create := New(Spec[NoInput, secreted]{
		Name:    "create",
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog keys create"},
		Local:   true,
		Run:     noop[NoInput, secreted],
		Secret:  func(secreted) string { return "" },
		Done:    func(NoInput, secreted, time.Time) string { return "" },
	})
	list := NewList(
		ListSpec[NoInput, item]{
			Name:    "list",
			Short:   "S",
			Long:    "S.",
			Example: []string{"prog keys list"},
			Local:   true,
			Columns: itemColumns,
			NoRows:  "None.",
			Run:     noop[NoInput, []item],
		},
	)
	unsaid := NewEnd(EndSpec[getIn, item]{
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog keys delete 7"},
		Target:  func(getIn) item { return item{} },
		Of:      func(item) Ended { return Ended{} },
		Revoke:  func(Ctx, string) error { return nil },
		Get:     func(Ctx, string) (item, error) { return item{}, nil },
	})

	for _, tt := range []struct {
		name  string
		nodes []Node
		want  string
	}{
		{"a target with revoked", []Node{byHand}, "creds delete: " + errNotEnd.Error()},
		{"beside a Secret, a target with no revoked", []Node{create, list, plain}, "keys delete: " + errNotEnd.Error()},
		{"NewEnd with no Secret beside it", []Node{list, endOf()}, "keys delete: " + errEndAlone.Error()},
		{"NewEnd that says nothing of Own", []Node{create, list, unsaid}, "keys delete: " + errOwn.Error()},
	} {
		group := "keys"
		if tt.nodes[0] == byHand {
			group = "creds"
		}

		_, err := build(
			"prog",
			"A program",
			allowedAliases(),
			nil,
			Group{Name: group, Short: "S", Commands: tt.nodes},
		)
		require.ErrorContains(t, err, tt.want, tt.name)
	}

	_, err := build(
		"prog",
		"A program",
		allowedAliases(),
		nil,
		Group{Name: "keys", Short: "S", Commands: []Node{create, list, endOf()}},
	)
	require.NoError(t, err)
}
