package cli

import (
	"encoding/json"
	"strings"
	"testing"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"tailscale.com/types/key"
)

// sampleNode builds a fully-populated node with valid machine/node keys so the
// table renderer's UnmarshalText/ParseAddr paths exercise real data.
func sampleNode(t *testing.T) apiv1.Node {
	t.Helper()

	mkey, err := key.NewMachine().Public().MarshalText()
	if err != nil {
		t.Fatalf("machine key: %v", err)
	}

	nkey, err := key.NewNode().Public().MarshalText()
	if err != nil {
		t.Fatalf("node key: %v", err)
	}

	return apiv1.Node{
		ID:          apiv1.NewOptUint64(7),
		Name:        apiv1.NewOptString("host7"),
		GivenName:   apiv1.NewOptString("host7"),
		MachineKey:  apiv1.NewOptString(string(mkey)),
		NodeKey:     apiv1.NewOptString(string(nkey)),
		User:        apiv1.NewOptUser(apiv1.User{Name: apiv1.NewOptString("alice")}),
		IpAddresses: []string{"100.64.0.7", "fd7a:115c:a1e0::7"},
		Online:      apiv1.NewOptBool(true),
		// Expiry, LastSeen, Tags deliberately unset.
	}
}

// TestFormatOutputValueWithUnsetOptional guards against a regression where the
// generated API types, passed by value with unset optional fields, fail to
// marshal because stdlib reflection calls Opt*.MarshalJSON directly.
func TestFormatOutputValueWithUnsetOptional(t *testing.T) {
	cases := map[string]any{
		"user":       apiv1.User{ID: apiv1.NewOptUint64(1), Name: apiv1.NewOptString("alice")},
		"node":       sampleNode(t),
		"preauthkey": apiv1.PreAuthKey{ID: apiv1.NewOptUint64(2), Key: apiv1.NewOptString("abc")},
		"apikey":     apiv1.ApiKey{ID: apiv1.NewOptUint64(3), Prefix: apiv1.NewOptString("pref")},
	}

	formats := []string{outputFormatJSON, outputFormatJSONLine, outputFormatYAML}

	for name, val := range cases {
		for _, format := range formats {
			// Single value.
			out, err := formatOutput(val, "", format)
			if err != nil {
				t.Fatalf("formatOutput(%s, %s) value: %v", name, format, err)
			}

			if strings.TrimSpace(out) == "" {
				t.Errorf("formatOutput(%s, %s) value: empty output", name, format)
			}

			// Slice of values (the "list" commands).
			sliceOut, err := formatOutput([]any{val}, "", format)
			if err != nil {
				t.Fatalf("formatOutput(%s, %s) slice: %v", name, format, err)
			}

			if strings.TrimSpace(sliceOut) == "" {
				t.Errorf("formatOutput(%s, %s) slice: empty output", name, format)
			}
		}
	}
}

// TestFormatOutputJSONShape pins that a value-typed object serialises by its
// JSON field names (not the Go struct shape) and omits unset optionals.
func TestFormatOutputJSONShape(t *testing.T) {
	user := apiv1.User{ID: apiv1.NewOptUint64(1), Name: apiv1.NewOptString("alice")}

	out, err := formatOutput(user, "", outputFormatJSON)
	if err != nil {
		t.Fatalf("formatOutput: %v", err)
	}

	var decoded map[string]any

	err = json.Unmarshal([]byte(out), &decoded)
	if err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}

	if decoded["name"] != "alice" || decoded["id"] != float64(1) {
		t.Errorf("unexpected JSON shape: %s", out)
	}

	if _, present := decoded["displayName"]; present {
		t.Errorf("unset optional should be omitted, got: %s", out)
	}
}

// TestNodesToPtables exercises the default table renderer, whose manual
// MachineKey/NodeKey UnmarshalText and IP ParseAddr have no other coverage.
func TestNodesToPtables(t *testing.T) {
	data, err := nodesToPtables([]apiv1.Node{sampleNode(t)})
	if err != nil {
		t.Fatalf("nodesToPtables: %v", err)
	}

	if len(data) != 2 {
		t.Fatalf("want header + 1 row, got %d rows", len(data))
	}

	row := strings.Join(data[1], "|")
	for _, want := range []string{"host7", "alice", "100.64.0.7", "fd7a:115c:a1e0::7"} {
		if !strings.Contains(row, want) {
			t.Errorf("row missing %q: %s", want, row)
		}
	}
}

// TestNodesToPtablesEmptyNodeKey documents that a missing NodeKey makes the
// table render fail loudly rather than silently — so a decode regression that
// drops NodeKey over HTTP is caught at the CLI, not just in -o json.
func TestNodesToPtablesEmptyNodeKey(t *testing.T) {
	node := sampleNode(t)
	node.NodeKey = apiv1.OptString{}

	_, err := nodesToPtables([]apiv1.Node{node})
	if err == nil {
		t.Error("expected error for empty NodeKey, got nil")
	}
}

// TestNodeRoutesToPtables renders the list-routes table, which has zero
// integration coverage.
func TestNodeRoutesToPtables(t *testing.T) {
	node := sampleNode(t)
	node.SubnetRoutes = []string{"10.0.0.0/24"}
	node.ApprovedRoutes = []string{"10.0.0.0/24"}

	data := nodeRoutesToPtables([]apiv1.Node{node})
	if len(data) != 2 {
		t.Fatalf("want header + 1 row, got %d rows", len(data))
	}

	if !strings.Contains(strings.Join(data[1], "|"), "10.0.0.0/24") {
		t.Errorf("route row missing approved route: %v", data[1])
	}
}
