package command

import (
	"net/netip"
	"testing"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/stretchr/testify/require"
)

// TestIfMatch: a write on the target sends the revision the builder read
// for it; a write on another entity, and a run with no target, send none.
func TestIfMatch(t *testing.T) {
	t.Parallel()

	c := &run{}
	require.Nil(t, c.IfMatch("12"), "no target")

	c.guard.Store(guardOf(struct {
		Node guarded `arg:"node"`
	}{guarded{ID: "12", Revision: "r2"}}))
	require.Equal(t, new(`"r2"`), c.IfMatch("12"))
	require.Nil(t, c.IfMatch("13"), "another entity")
	require.Nil(t, c.Expect("12"), "a revision is no token")

	c.guard.Store(&revision{id: "12", rev: "tok", token: true})
	require.Nil(t, c.IfMatch("12"), "a token is no revision")
}

// TestExpect: a write on the target sends the token the question gave, in
// place of a revision; another entity, and a run before any question, none.
func TestExpect(t *testing.T) {
	t.Parallel()

	c := &run{}
	require.Nil(t, c.Expect("3"), "no question yet")

	c.guard.Store(&revision{id: "3", rev: "0123456789abcdef", token: true})
	require.Equal(t, new("0123456789abcdef"), c.Expect("3"))
	require.Nil(t, c.Expect("4"), "another entity")
}

// TestGuardOf: the target is the first argument that is an entity; one
// with no revision guards nothing.
func TestGuardOf(t *testing.T) {
	t.Parallel()

	type routes struct {
		Prefix netip.Prefix `arg:"prefix"`
		Node   guarded      `arg:"node"`
		Other  guarded      `arg:"other"`
	}

	require.Equal(
		t,
		&revision{id: "12", rev: "r1"},
		guardOf(
			routes{
				Node:  guarded{ID: "12", Revision: "r1"},
				Other: guarded{ID: "13", Revision: "r9"},
			},
		),
	)
	require.Nil(
		t,
		guardOf(
			routes{Node: guarded{ID: "12"}, Other: guarded{ID: "13", Revision: "r9"}},
		),
		"a target with no revision guards nothing",
	)
	require.Nil(t, guardOf(struct {
		User clientv0.User `arg:"user"`
	}{User: clientv0.User{Id: "3"}}))
	require.Nil(t, guardOf(NoInput{}), "no target, no guard")
}

// guarded is an entity with a revision, as a node is.
type guarded struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision string `json:"revision"`
}
