package policyv2

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tailscale/hujson"
	"tailscale.com/tailcfg"
)

func TestUnmarshalPolicy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *ACLPolicy
		wantErr error
	}{
		{
			name:  "empty",
			input: "{}",
			want:  &ACLPolicy{},
		},
		{
			name: "basic-types",
			input: `
{
	"groups": {
		"group:example": [
			"testuser@headscale.net",
		],
	},

	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"group:example",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: &ACLPolicy{
				Groups: Groups{
					Group("group:example"): []Username{"testuser@headscale.net"},
				},
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							Group("group:example"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Host("host-1"),
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policy ACLPolicy
			ast, err := hujson.Parse([]byte(tt.input))
			if err != nil {
				t.Fatalf("parsing hujson: %s", err)
			}

			ast.Standardize()
			acl := ast.Pack()

			if err := json.Unmarshal(acl, &policy); err != nil {
				// TODO: check error type
				t.Fatalf("unmarshaling json: %s", err)
			}

			if diff := cmp.Diff(tt.want, &policy); diff != "" {
				t.Fatalf("unexpected policy (-want +got):\n%s", diff)
			}
		})
	}
}
