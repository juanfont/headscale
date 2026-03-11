package v2

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	xmaps "golang.org/x/exp/maps"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

// TestUnmarshalPolicy tests the unmarshalling of JSON into Policy objects and the marshalling
// back to JSON (round-trip). It ensures that:
// 1. JSON can be correctly unmarshalled into a Policy object
// 2. A Policy object can be correctly marshalled back to JSON
// 3. The unmarshalled Policy matches the expected Policy
// 4. The marshalled and then unmarshalled Policy is semantically equivalent to the original
//    (accounting for nil vs empty map/slice differences)
//
// This test also verifies that all the required struct fields are properly marshalled and
// unmarshalled, maintaining semantic equivalence through a complete JSON round-trip.

// TestMarshalJSON tests explicit marshalling of Policy objects to JSON.
// This test ensures our custom MarshalJSON methods properly encode
// the various data structures used in the Policy.
func TestMarshalJSON(t *testing.T) {
	// Create a complex test policy
	policy := &Policy{
		Groups: Groups{
			Group("group:example"): []Username{Username("user@example.com")},
		},
		Hosts: Hosts{
			"host-1": Prefix(mp("100.100.100.100/32")),
		},
		TagOwners: TagOwners{
			Tag("tag:test"): Owners{up("user@example.com")},
		},
		ACLs: []ACL{
			{
				Action:   "accept",
				Protocol: "tcp",
				Sources: Aliases{
					new(Username("user@example.com")),
				},
				Destinations: []AliasWithPorts{
					{
						Alias: new(Username("other@example.com")),
						Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
					},
				},
			},
		},
	}

	// Marshal the policy to JSON
	marshalled, err := json.MarshalIndent(policy, "", "  ")
	require.NoError(t, err)

	// Make sure all expected fields are present in the JSON
	jsonString := string(marshalled)
	assert.Contains(t, jsonString, "group:example")
	assert.Contains(t, jsonString, "user@example.com")
	assert.Contains(t, jsonString, "host-1")
	assert.Contains(t, jsonString, "100.100.100.100/32")
	assert.Contains(t, jsonString, "tag:test")
	assert.Contains(t, jsonString, "accept")
	assert.Contains(t, jsonString, "tcp")
	assert.Contains(t, jsonString, "80")

	// Unmarshal back to verify round trip
	var roundTripped Policy

	err = json.Unmarshal(marshalled, &roundTripped)
	require.NoError(t, err)

	// Compare the original and round-tripped policies
	cmps := append(util.Comparers,
		cmp.Comparer(func(x, y Prefix) bool {
			return x == y
		}),
		cmpopts.IgnoreUnexported(Policy{}),
		cmpopts.EquateEmpty(),
	)

	if diff := cmp.Diff(policy, &roundTripped, cmps...); diff != "" {
		t.Fatalf("round trip policy (-original +roundtripped):\n%s", diff)
	}
}

func TestUnmarshalPolicy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Policy
		wantErr string
	}{
		{
			name:  "empty",
			input: "{}",
			want:  &Policy{},
		},
		{
			name: "groups",
			input: `
{
	"groups": {
		"group:example": [
			"derp@headscale.net",
		],
	},
}
`,
			want: &Policy{
				Groups: Groups{
					Group("group:example"): []Username{Username("derp@headscale.net")},
				},
			},
		},
		{
			name: "basic-types",
			input: `
{
	"groups": {
		"group:example": [
			"testuser@headscale.net",
		],
		"group:other": [
			"otheruser@headscale.net",
		],
		"group:noat": [
			"noat@",
		],
	},

	"tagOwners": {
		"tag:user": ["testuser@headscale.net"],
		"tag:group": ["group:other"],
		"tag:userandgroup": ["testuser@headscale.net", "group:other"],
	},

	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
		"outside": "192.168.0.0/16",
	},

	"acls": [
	    // All
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["*"],
			"dst": ["*:*"],
		},
		// Users
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["testuser@headscale.net"],
			"dst": ["otheruser@headscale.net:80"],
		},
		// Groups
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["group:example"],
			"dst": ["group:other:80"],
		},
		// Tailscale IP
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["100.101.102.103"],
			"dst": ["100.101.102.104:80"],
		},
		// Subnet
		{
			"action": "accept",
			"proto": "udp",
			"src": ["10.0.0.0/8"],
			"dst": ["172.16.0.0/16:80"],
		},
		// Hosts
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["subnet-1"],
			"dst": ["host-1:80-88"],
		},
		// Tags
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["tag:group"],
			"dst": ["tag:user:80,443"],
		},
		// Autogroup
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["tag:group"],
			"dst": ["autogroup:internet:80"],
		},
	],
}
`,
			want: &Policy{
				Groups: Groups{
					Group("group:example"): []Username{Username("testuser@headscale.net")},
					Group("group:other"):   []Username{Username("otheruser@headscale.net")},
					Group("group:noat"):    []Username{Username("noat@")},
				},
				TagOwners: TagOwners{
					Tag("tag:user"):         Owners{up("testuser@headscale.net")},
					Tag("tag:group"):        Owners{gp("group:other")},
					Tag("tag:userandgroup"): Owners{up("testuser@headscale.net"), gp("group:other")},
				},
				Hosts: Hosts{
					"host-1":   Prefix(mp("100.100.100.100/32")),
					"subnet-1": Prefix(mp("100.100.101.100/24")),
					"outside":  Prefix(mp("192.168.0.0/16")),
				},
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							Wildcard,
						},
						Destinations: []AliasWithPorts{
							{
								// TODO(kradalby): Should this be host?
								// It is:
								// Includes any destination (no restrictions).
								Alias: Wildcard,
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							new(Username("testuser@headscale.net")),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: new(Username("otheruser@headscale.net")),
								Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							gp("group:example"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: gp("group:other"),
								Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							pp("100.101.102.103/32"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: pp("100.101.102.104/32"),
								Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "udp",
						Sources: Aliases{
							pp("10.0.0.0/8"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: pp("172.16.0.0/16"),
								Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							hp("subnet-1"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: hp("host-1"),
								Ports: []tailcfg.PortRange{{First: 80, Last: 88}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							tp("tag:group"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: tp("tag:user"),
								Ports: []tailcfg.PortRange{
									{First: 80, Last: 80},
									{First: 443, Last: 443},
								},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							tp("tag:group"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: agp("autogroup:internet"),
								Ports: []tailcfg.PortRange{
									{First: 80, Last: 80},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "2652-asterix-error-better-explain",
			input: `
{
	"ssh": [
		{
			"action": "accept",
			"src": [
				"*"
			],
			"dst": [
				"*"
			],
			"users": ["root"]
		}
	]
}
			`,
			wantErr: "alias not supported for SSH source: v2.Asterix",
		},
		{
			name: "invalid-username",
			input: `
{
	"groups": {
		"group:example": [
			"valid@",
			"invalid",
		],
	},
}
`,
			wantErr: `username must contain @, got: "invalid"`,
		},
		{
			name: "invalid-group",
			input: `
{
	"groups": {
		"grou:example": [
			"valid@",
		],
	},
}
`,
			wantErr: `group must start with 'group:', got: "grou:example"`,
		},
		{
			name: "group-in-group",
			input: `
{
	"groups": {
		"group:inner": [],
		"group:example": [
			"group:inner",
		],
	},
}
`,
			// wantErr: `username must contain @, got: "group:inner"`,
			wantErr: `nested groups are not allowed: found "group:inner" inside "group:example"`,
		},
		{
			name: "invalid-addr",
			input: `
{
	"hosts": {
		"derp": "10.0",
	},
}
`,
			wantErr: `hostname contains invalid IP address: hostname "derp" address "10.0"`,
		},
		{
			name: "invalid-prefix",
			input: `
{
			"hosts": {
				"derp": "10.0/42",
			},
}
`,
			wantErr: `hostname contains invalid IP address: hostname "derp" address "10.0/42"`,
		},
		// TODO(kradalby): Figure out why this doesn't work.
		// 		{
		// 			name: "invalid-hostname",
		// 			input: `
		// {
		// 			"hosts": {
		// 				"derp:merp": "10.0.0.0/31",
		// 			},
		// }
		// `,
		// 			wantErr: `Hostname "derp:merp" is invalid`,
		// 		},
		{
			name: "invalid-auto-group",
			input: `
{
	"acls": [
		// Autogroup
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["tag:group"],
			"dst": ["autogroup:invalid:80"],
		},
	],
}
`,
			wantErr: `invalid autogroup: got "autogroup:invalid", must be one of [autogroup:internet autogroup:member autogroup:nonroot autogroup:tagged autogroup:self]`,
		},
		{
			name: "undefined-hostname-errors-2490",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "user1"
      ],
      "dst": [
        "user1:*"
      ]
    }
  ]
}
`,
			wantErr: `host not defined in policy: "user1"`,
		},
		{
			name: "defined-hostname-does-not-err-2490",
			input: `
{
  "hosts": {
		"user1": "100.100.100.100",
  },
  "acls": [
    {
      "action": "accept",
      "src": [
        "user1"
      ],
      "dst": [
        "user1:*"
      ]
    }
  ]
}
`,
			want: &Policy{
				Hosts: Hosts{
					"user1": Prefix(mp("100.100.100.100/32")),
				},
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							hp("user1"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: hp("user1"),
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
				},
			},
		},
		{
			name: "autogroup:internet-in-dst-allowed",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "10.0.0.1"
      ],
      "dst": [
        "autogroup:internet:*"
      ]
    }
  ]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							pp("10.0.0.1/32"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: new(AutoGroup("autogroup:internet")),
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
				},
			},
		},
		{
			name: "autogroup:internet-in-src-not-allowed",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "autogroup:internet"
      ],
      "dst": [
        "10.0.0.1:*"
      ]
    }
  ]
}
`,
			wantErr: `autogroup:internet can only be used in ACL destinations`,
		},
		{
			name: "autogroup:internet-in-ssh-src-not-allowed",
			input: `
{
  "ssh": [
    {
      "action": "accept",
      "src": [
        "autogroup:internet"
      ],
      "dst": [
        "tag:test"
      ]
    }
  ]
}
`,
			wantErr: `tag not defined in policy: "tag:test"`,
		},
		{
			name: "autogroup:internet-in-ssh-dst-not-allowed",
			input: `
{
  "ssh": [
    {
      "action": "accept",
      "src": [
        "tag:test"
      ],
      "dst": [
        "autogroup:internet"
      ]
    }
  ]
}
`,
			wantErr: `autogroup:internet can only be used in ACL destinations`,
		},
		{
			name: "ssh-basic",
			input: `
{
  "groups": {
    "group:admins": ["admin@example.com"]
  },
  "tagOwners": {
    "tag:servers": ["group:admins"]
  },
  "ssh": [
    {
      "action": "accept",
      "src": [
        "group:admins"
      ],
      "dst": [
        "tag:servers"
      ],
      "users": ["root", "admin"]
    }
  ]
}
`,
			want: &Policy{
				Groups: Groups{
					Group("group:admins"): []Username{Username("admin@example.com")},
				},
				TagOwners: TagOwners{
					Tag("tag:servers"): Owners{gp("group:admins")},
				},
				SSHs: []SSH{
					{
						Action: "accept",
						Sources: SSHSrcAliases{
							gp("group:admins"),
						},
						Destinations: SSHDstAliases{
							tp("tag:servers"),
						},
						Users: []SSHUser{
							SSHUser("root"),
							SSHUser("admin"),
						},
					},
				},
			},
		},
		{
			name: "ssh-with-tag-and-user",
			input: `
{
  "tagOwners": {
    "tag:web": ["admin@example.com"],
    "tag:server": ["admin@example.com"]
  },
  "ssh": [
    {
      "action": "accept",
      "src": [
        "tag:web"
      ],
      "dst": [
        "tag:server"
      ],
      "users": ["*"]
    }
  ]
}
`,
			want: &Policy{
				TagOwners: TagOwners{
					Tag("tag:web"):    Owners{new(Username("admin@example.com"))},
					Tag("tag:server"): Owners{new(Username("admin@example.com"))},
				},
				SSHs: []SSH{
					{
						Action: "accept",
						Sources: SSHSrcAliases{
							tp("tag:web"),
						},
						Destinations: SSHDstAliases{
							tp("tag:server"),
						},
						Users: []SSHUser{
							SSHUser("*"),
						},
					},
				},
			},
		},
		{
			name: "ssh-with-check-period",
			input: `
{
  "groups": {
    "group:admins": ["admin@example.com"]
  },
  "ssh": [
    {
      "action": "check",
      "src": [
        "group:admins"
      ],
      "dst": [
        "autogroup:self"
      ],
      "users": ["root"],
      "checkPeriod": "24h"
    }
  ]
}
`,
			want: &Policy{
				Groups: Groups{
					Group("group:admins"): []Username{Username("admin@example.com")},
				},
				SSHs: []SSH{
					{
						Action: "check",
						Sources: SSHSrcAliases{
							gp("group:admins"),
						},
						Destinations: SSHDstAliases{
							agp("autogroup:self"),
						},
						Users: []SSHUser{
							SSHUser("root"),
						},
						CheckPeriod: &SSHCheckPeriod{Duration: 24 * time.Hour},
					},
				},
			},
		},
		{
			name: "group-must-be-defined-acl-src",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "group:notdefined"
      ],
      "dst": [
        "autogroup:internet:*"
      ]
    }
  ]
}
`,
			wantErr: `group not defined in policy: "group:notdefined"`,
		},
		{
			name: "group-must-be-defined-acl-dst",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "*"
      ],
      "dst": [
        "group:notdefined:*"
      ]
    }
  ]
}
`,
			wantErr: `group not defined in policy: "group:notdefined"`,
		},
		{
			name: "group-must-be-defined-acl-ssh-src",
			input: `
{
  "ssh": [
    {
      "action": "accept",
      "src": [
        "group:notdefined"
      ],
      "dst": [
        "user@"
      ]
    }
  ]
}
`,
			wantErr: `user destination requires source to contain only that same user "user@"`,
		},
		{
			name: "group-must-be-defined-acl-tagOwner",
			input: `
{
  "tagOwners": {
    "tag:test": ["group:notdefined"],
  },
}
`,
			wantErr: `group not defined in policy: "group:notdefined"`,
		},
		{
			name: "group-must-be-defined-acl-autoapprover-route",
			input: `
{
  "autoApprovers": {
    "routes": {
      "10.0.0.0/16": ["group:notdefined"]
    }
  },
}
`,
			wantErr: `group not defined in policy: "group:notdefined"`,
		},
		{
			name: "group-must-be-defined-acl-autoapprover-exitnode",
			input: `
{
  "autoApprovers": {
    "exitNode": ["group:notdefined"]
   },
}
`,
			wantErr: `group not defined in policy: "group:notdefined"`,
		},
		{
			name: "tag-must-be-defined-acl-src",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "tag:notdefined"
      ],
      "dst": [
        "autogroup:internet:*"
      ]
    }
  ]
}
`,
			wantErr: `tag not defined in policy: "tag:notdefined"`,
		},
		{
			name: "tag-must-be-defined-acl-dst",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "*"
      ],
      "dst": [
        "tag:notdefined:*"
      ]
    }
  ]
}
`,
			wantErr: `tag not defined in policy: "tag:notdefined"`,
		},
		{
			name: "tag-must-be-defined-acl-ssh-src",
			input: `
{
  "ssh": [
    {
      "action": "accept",
      "src": [
        "tag:notdefined"
      ],
      "dst": [
        "user@"
      ]
    }
  ]
}
`,
			wantErr: `tag not defined in policy: "tag:notdefined"`,
		},
		{
			name: "tag-must-be-defined-acl-ssh-dst",
			input: `
{
  "groups": {
  	"group:defined": ["user@"],
  },
  "ssh": [
    {
      "action": "accept",
      "src": [
        "group:defined"
      ],
      "dst": [
        "tag:notdefined",
      ],
    }
  ]
}
`,
			wantErr: `tag not defined in policy: "tag:notdefined"`,
		},
		{
			name: "tag-must-be-defined-acl-autoapprover-route",
			input: `
{
  "autoApprovers": {
    "routes": {
      "10.0.0.0/16": ["tag:notdefined"]
    }
  },
}
`,
			wantErr: `tag not defined in policy: "tag:notdefined"`,
		},
		{
			name: "tag-must-be-defined-acl-autoapprover-exitnode",
			input: `
{
  "autoApprovers": {
    "exitNode": ["tag:notdefined"]
   },
}
`,
			wantErr: `tag not defined in policy: "tag:notdefined"`,
		},
		{
			name: "missing-dst-port-is-err",
			input: `
			{
  "acls": [
    {
      "action": "accept",
      "src": [
        "*"
      ],
      "dst": [
        "100.64.0.1"
      ]
    }
  ]
}
`,
			wantErr: `hostport must contain a colon`,
		},
		{
			name: "dst-port-zero-is-err",
			input: `
			{
  "acls": [
    {
      "action": "accept",
      "src": [
        "*"
      ],
      "dst": [
        "100.64.0.1:0"
      ]
    }
  ]
}
`,
			wantErr: `first port must be >0, or use '*' for wildcard`,
		},
		{
			name: "disallow-unsupported-fields",
			input: `
{
  // rules doesnt exists, we have "acls"
  "rules": [
  ]
}
`,
			wantErr: `unknown field: "rules"`,
		},
		{
			name: "disallow-unsupported-fields-nested",
			input: `
{
    "acls": [
        { "action": "accept", "BAD": ["FOO:BAR:FOO:BAR"], "NOT": ["BAD:BAD:BAD:BAD"] }
      ]
}
`,
			wantErr: `unknown field`,
		},
		{
			name: "invalid-group-name",
			input: `
{
  "groups": {
    "group:test": ["user@example.com"],
    "INVALID_GROUP_FIELD": ["user@example.com"]
  }
}
`,
			wantErr: `group must start with 'group:', got: "INVALID_GROUP_FIELD"`,
		},
		{
			name: "invalid-group-datatype",
			input: `
{
  "groups": {
    "group:test": ["user@example.com"],
    "group:invalid": "should fail"
  }
}
`,
			wantErr: `group value must be an array of users: group "group:invalid" got string: "should fail"`,
		},
		{
			name: "invalid-group-name-and-datatype-fails-on-name-first",
			input: `
{
  "groups": {
    "group:test": ["user@example.com"],
    "INVALID_GROUP_FIELD": "should fail"
  }
}
`,
			wantErr: `group must start with 'group:', got: "INVALID_GROUP_FIELD"`,
		},
		{
			name: "disallow-unsupported-fields-hosts-level",
			input: `
{
  "hosts": {
    "host1": "10.0.0.1",
    "INVALID_HOST_FIELD": "should fail"
  }
}
`,
			wantErr: `hostname contains invalid IP address: hostname "INVALID_HOST_FIELD" address "should fail"`,
		},
		{
			name: "disallow-unsupported-fields-tagowners-level",
			input: `
{
  "tagOwners": {
    "tag:test": ["user@example.com"],
    "INVALID_TAG_FIELD": "should fail"
  }
}
`,
			wantErr: `tag must start with 'tag:', got: "INVALID_TAG_FIELD"`,
		},
		{
			name: "disallow-unsupported-fields-acls-level",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "proto": "tcp",
      "src": ["*"],
      "dst": ["*:*"],
      "INVALID_ACL_FIELD": "should fail"
    }
  ]
}
`,
			wantErr: `unknown field: "INVALID_ACL_FIELD"`,
		},
		{
			name: "disallow-unsupported-fields-ssh-level",
			input: `
{
  "ssh": [
    {
      "action": "accept",
      "src": ["user@example.com"],
      "dst": ["user@example.com"],
      "users": ["root"],
      "INVALID_SSH_FIELD": "should fail"
    }
  ]
}
`,
			wantErr: `unknown field: "INVALID_SSH_FIELD"`,
		},
		{
			name: "disallow-unsupported-fields-policy-level",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "proto": "tcp",
      "src": ["*"],
      "dst": ["*:*"]
    }
  ],
  "INVALID_POLICY_FIELD": "should fail at policy level"
}
`,
			wantErr: `unknown field: "INVALID_POLICY_FIELD"`,
		},
		{
			name: "disallow-unsupported-fields-autoapprovers-level",
			input: `
{
  "autoApprovers": {
    "routes": {
      "10.0.0.0/8": ["user@example.com"]
    },
    "exitNode": ["user@example.com"],
    "INVALID_AUTO_APPROVER_FIELD": "should fail"
  }
}
`,
			wantErr: `unknown field: "INVALID_AUTO_APPROVER_FIELD"`,
		},
		// headscale-admin uses # in some field names to add metadata, so we will ignore
		// those to ensure it doesnt break.
		// https://github.com/GoodiesHQ/headscale-admin/blob/214a44a9c15c92d2b42383f131b51df10c84017c/src/lib/common/acl.svelte.ts#L38
		{
			name: "hash-fields-are-allowed-but-ignored",
			input: `
{
  "acls": [
    {
      "#ha-test": "SOME VALUE",
      "action": "accept",
      "src": [
        "10.0.0.1"
      ],
      "dst": [
        "autogroup:internet:*"
      ]
    }
  ]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							pp("10.0.0.1/32"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: new(AutoGroup("autogroup:internet")),
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
				},
			},
		},
		{
			name: "ssh-asterix-invalid-acl-input",
			input: `
{
	"ssh": [
		{
			"action": "accept",
			"src": [
				"user@example.com"
			],
			"dst": [
				"user@example.com"
			],
			"users": ["root"],
			"proto": "tcp"
		}
	]
}
`,
			wantErr: `unknown field: "proto"`,
		},
		{
			name: "protocol-wildcard-not-allowed",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"proto": "*",
			"src": ["*"],
			"dst": ["*:*"]
		}
	]
}
`,
			wantErr: `proto name "*" not known; use protocol number 0-255 or protocol name (icmp, tcp, udp, etc.)`,
		},
		{
			name: "protocol-case-insensitive-uppercase",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"proto": "ICMP",
			"src": ["*"],
			"dst": ["*:*"]
		}
	]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "icmp",
						Sources: Aliases{
							Wildcard,
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Wildcard,
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
				},
			},
		},
		{
			name: "protocol-case-insensitive-mixed",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"proto": "IcmP",
			"src": ["*"],
			"dst": ["*:*"]
		}
	]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "icmp",
						Sources: Aliases{
							Wildcard,
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Wildcard,
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
				},
			},
		},
		{
			name: "protocol-leading-zero-not-permitted",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"proto": "0",
			"src": ["*"],
			"dst": ["*:*"]
		}
	]
}
`,
			wantErr: `leading 0 not permitted in protocol number: "0"`,
		},
		{
			name: "protocol-empty-applies-to-tcp-udp-only",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"src": ["*"],
			"dst": ["*:80"]
		}
	]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "",
						Sources: Aliases{
							Wildcard,
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Wildcard,
								Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
				},
			},
		},
		{
			name: "protocol-icmp-with-specific-port-not-allowed",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"proto": "icmp",
			"src": ["*"],
			"dst": ["*:80"]
		}
	]
}
`,
			wantErr: `protocol does not support specific ports: "icmp", only "*" is allowed`,
		},
		{
			name: "protocol-icmp-with-wildcard-port-allowed",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"proto": "icmp",
			"src": ["*"],
			"dst": ["*:*"]
		}
	]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "icmp",
						Sources: Aliases{
							Wildcard,
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Wildcard,
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
				},
			},
		},
		{
			name: "protocol-gre-with-specific-port-not-allowed",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"proto": "gre",
			"src": ["*"],
			"dst": ["*:443"]
		}
	]
}
`,
			wantErr: `protocol does not support specific ports: "gre", only "*" is allowed`,
		},
		{
			name: "protocol-tcp-with-specific-port-allowed",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["*"],
			"dst": ["*:80"]
		}
	]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							Wildcard,
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Wildcard,
								Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
				},
			},
		},
		{
			name: "protocol-udp-with-specific-port-allowed",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"proto": "udp",
			"src": ["*"],
			"dst": ["*:53"]
		}
	]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "udp",
						Sources: Aliases{
							Wildcard,
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Wildcard,
								Ports: []tailcfg.PortRange{{First: 53, Last: 53}},
							},
						},
					},
				},
			},
		},
		{
			name: "protocol-sctp-with-specific-port-allowed",
			input: `
{
	"acls": [
		{
			"action": "accept",
			"proto": "sctp",
			"src": ["*"],
			"dst": ["*:9000"]
		}
	]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "sctp",
						Sources: Aliases{
							Wildcard,
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Wildcard,
								Ports: []tailcfg.PortRange{{First: 9000, Last: 9000}},
							},
						},
					},
				},
			},
		},
		{
			name: "tags-can-own-other-tags",
			input: `
{
  "tagOwners": {
    "tag:bigbrother": [],
    "tag:smallbrother": ["tag:bigbrother"],
  },
  "acls": [
    {
      "action": "accept",
      "proto": "tcp",
      "src": ["*"],
      "dst": ["tag:smallbrother:9000"]
    }
  ]
}
`,
			want: &Policy{
				TagOwners: TagOwners{
					Tag("tag:bigbrother"):   {},
					Tag("tag:smallbrother"): {new(Tag("tag:bigbrother"))},
				},
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							Wildcard,
						},
						Destinations: []AliasWithPorts{
							{
								Alias: new(Tag("tag:smallbrother")),
								Ports: []tailcfg.PortRange{{First: 9000, Last: 9000}},
							},
						},
					},
				},
			},
		},
		{
			name: "tag-owner-references-undefined-tag",
			input: `
{
  "tagOwners": {
    "tag:child": ["tag:nonexistent"],
  },
}
`,
			wantErr: `tag "tag:child" references undefined tag "tag:nonexistent"`,
		},
		// SSH source/destination validation tests (#3009, #3010)
		{
			name: "ssh-tag-to-user-rejected",
			input: `
{
  "tagOwners": {"tag:server": ["admin@"]},
  "ssh": [{
    "action": "accept",
    "src": ["tag:server"],
    "dst": ["admin@"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			wantErr: "tags in SSH source cannot access user-owned devices",
		},
		{
			name: "ssh-autogroup-tagged-to-user-rejected",
			input: `
{
  "ssh": [{
    "action": "accept",
    "src": ["autogroup:tagged"],
    "dst": ["admin@"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			wantErr: "tags in SSH source cannot access user-owned devices",
		},
		{
			name: "ssh-tag-to-autogroup-self-rejected",
			input: `
{
  "tagOwners": {"tag:server": ["admin@"]},
  "ssh": [{
    "action": "accept",
    "src": ["tag:server"],
    "dst": ["autogroup:self"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			wantErr: "autogroup:self destination requires source to contain only users or groups",
		},
		{
			name: "ssh-group-to-user-rejected",
			input: `
{
  "groups": {"group:admins": ["admin@", "user1@"]},
  "ssh": [{
    "action": "accept",
    "src": ["group:admins"],
    "dst": ["admin@"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			wantErr: `user destination requires source to contain only that same user "admin@"`,
		},
		{
			name: "ssh-same-user-to-user-allowed",
			input: `
{
  "ssh": [{
    "action": "accept",
    "src": ["admin@"],
    "dst": ["admin@"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			want: &Policy{
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{up("admin@")},
						Destinations: SSHDstAliases{up("admin@")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot)},
					},
				},
			},
		},
		{
			name: "ssh-group-to-autogroup-self-allowed",
			input: `
{
  "groups": {"group:admins": ["admin@", "user1@"]},
  "ssh": [{
    "action": "accept",
    "src": ["group:admins"],
    "dst": ["autogroup:self"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			want: &Policy{
				Groups: Groups{
					Group("group:admins"): []Username{Username("admin@"), Username("user1@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{agp("autogroup:self")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot)},
					},
				},
			},
		},
		{
			name: "ssh-autogroup-tagged-to-autogroup-member-rejected",
			input: `
{
  "ssh": [{
    "action": "accept",
    "src": ["autogroup:tagged"],
    "dst": ["autogroup:member"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			wantErr: "tags in SSH source cannot access autogroup:member",
		},
		{
			name: "ssh-autogroup-tagged-to-autogroup-tagged-allowed",
			input: `
{
  "ssh": [{
    "action": "accept",
    "src": ["autogroup:tagged"],
    "dst": ["autogroup:tagged"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			want: &Policy{
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:tagged")},
						Destinations: SSHDstAliases{agp("autogroup:tagged")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot)},
					},
				},
			},
		},
		{
			name: "ssh-wildcard-destination-rejected",
			input: `
{
  "groups": {"group:admins": ["admin@"]},
  "ssh": [{
    "action": "accept",
    "src": ["group:admins"],
    "dst": ["*"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			wantErr: "wildcard (*) is not supported as SSH destination",
		},
		{
			name: "ssh-group-to-tag-allowed",
			input: `
{
  "tagOwners": {"tag:server": ["admin@"]},
  "groups": {"group:admins": ["admin@"]},
  "ssh": [{
    "action": "accept",
    "src": ["group:admins"],
    "dst": ["tag:server"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			want: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("admin@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("admin@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot)},
					},
				},
			},
		},
		{
			name: "ssh-user-to-tag-allowed",
			input: `
{
  "tagOwners": {"tag:server": ["admin@"]},
  "ssh": [{
    "action": "accept",
    "src": ["admin@"],
    "dst": ["tag:server"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			want: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("admin@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{up("admin@")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot)},
					},
				},
			},
		},
		{
			name: "ssh-autogroup-member-to-autogroup-tagged-allowed",
			input: `
{
  "ssh": [{
    "action": "accept",
    "src": ["autogroup:member"],
    "dst": ["autogroup:tagged"],
    "users": ["autogroup:nonroot"]
  }]
}
`,
			want: &Policy{
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{agp("autogroup:tagged")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot)},
					},
				},
			},
		},
		// Issue #2754: IPv6 addresses with brackets in ACL destinations.
		{
			name: "2754-bracketed-ipv6-single-port",
			input: `
{
	"acls": [{
		"action": "accept",
		"src": ["alice@"],
		"dst": ["[fd7a:115c:a1e0::87e1]:443"]
	}]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							up("alice@"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: pp("fd7a:115c:a1e0::87e1/128"),
								Ports: []tailcfg.PortRange{{First: 443, Last: 443}},
							},
						},
					},
				},
			},
		},
		{
			name: "ssh-localpart-valid",
			input: `
{
  "tagOwners": {"tag:prod": ["admin@"]},
  "ssh": [{
    "action": "accept",
    "src": ["autogroup:member"],
    "dst": ["tag:prod"],
    "users": ["localpart:*@example.com"]
  }]
}
`,
			want: &Policy{
				TagOwners: TagOwners{
					Tag("tag:prod"): Owners{up("admin@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:prod")},
						Users:        []SSHUser{SSHUser("localpart:*@example.com")},
					},
				},
			},
		},
		{
			name: "2754-bracketed-ipv6-multiple-ports",
			input: `
{
	"acls": [{
		"action": "accept",
		"src": ["alice@"],
		"dst": ["[fd7a:115c:a1e0::87e1]:80,443"]
	}]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							up("alice@"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: pp("fd7a:115c:a1e0::87e1/128"),
								Ports: []tailcfg.PortRange{
									{First: 80, Last: 80},
									{First: 443, Last: 443},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ssh-localpart-with-other-users",
			input: `
{
  "tagOwners": {"tag:prod": ["admin@"]},
  "ssh": [{
    "action": "accept",
    "src": ["autogroup:member"],
    "dst": ["tag:prod"],
    "users": ["localpart:*@example.com", "root", "autogroup:nonroot"]
  }]
}
`,
			want: &Policy{
				TagOwners: TagOwners{
					Tag("tag:prod"): Owners{up("admin@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:prod")},
						Users:        []SSHUser{SSHUser("localpart:*@example.com"), "root", SSHUser(AutoGroupNonRoot)},
					},
				},
			},
		},
		{
			name: "2754-bracketed-ipv6-wildcard-port",
			input: `
{
	"acls": [{
		"action": "accept",
		"src": ["alice@"],
		"dst": ["[fd7a:115c:a1e0::87e1]:*"]
	}]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							up("alice@"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: pp("fd7a:115c:a1e0::87e1/128"),
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
				},
			},
		},
		{
			name: "2754-bracketed-ipv6-cidr-inside-rejected",
			input: `
{
	"acls": [{
		"action": "accept",
		"src": ["alice@"],
		"dst": ["[fd7a:115c:a1e0::/48]:443"]
	}]
}
`,
			wantErr: "square brackets are only valid around IPv6 addresses",
		},
		{
			name: "2754-bracketed-ipv6-port-range",
			input: `
{
	"acls": [{
		"action": "accept",
		"src": ["alice@"],
		"dst": ["[::1]:80-443"]
	}]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							up("alice@"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: pp("::1/128"),
								Ports: []tailcfg.PortRange{{First: 80, Last: 443}},
							},
						},
					},
				},
			},
		},
		{
			name: "2754-bracketed-ipv6-cidr-outside-brackets",
			input: `
{
	"acls": [{
		"action": "accept",
		"src": ["alice@"],
		"dst": ["[fd7a:115c:a1e0::2905]/128:80,443"]
	}]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							up("alice@"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: pp("fd7a:115c:a1e0::2905/128"),
								Ports: []tailcfg.PortRange{
									{First: 80, Last: 80},
									{First: 443, Last: 443},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "2754-bracketed-ipv4-rejected",
			input: `
{
	"acls": [{
		"action": "accept",
		"src": ["alice@"],
		"dst": ["[192.168.1.1]:80"]
	}]
}
`,
			wantErr: "square brackets are only valid around IPv6 addresses",
		},
		{
			name: "2754-bracketed-hostname-rejected",
			input: `
{
	"acls": [{
		"action": "accept",
		"src": ["alice@"],
		"dst": ["[my-hostname]:80"]
	}]
}
`,
			wantErr: "square brackets are only valid around IPv6 addresses",
		},
		{
			name: "ssh-localpart-invalid-no-at-sign",
			input: `
{
  "tagOwners": {"tag:prod": ["admin@"]},
  "ssh": [{
    "action": "accept",
    "src": ["autogroup:member"],
    "dst": ["tag:prod"],
    "users": ["localpart:foo"]
  }]
}
`,
			wantErr: "invalid localpart format",
		},
		{
			name: "ssh-localpart-invalid-non-wildcard",
			input: `
{
  "tagOwners": {"tag:prod": ["admin@"]},
  "ssh": [{
    "action": "accept",
    "src": ["autogroup:member"],
    "dst": ["tag:prod"],
    "users": ["localpart:alice@example.com"]
  }]
}
`,
			wantErr: "invalid localpart format",
		},
		{
			name: "ssh-localpart-invalid-empty-domain",
			input: `
{
  "tagOwners": {"tag:prod": ["admin@"]},
  "ssh": [{
    "action": "accept",
    "src": ["autogroup:member"],
    "dst": ["tag:prod"],
    "users": ["localpart:*@"]
  }]
}
`,
			wantErr: "invalid localpart format",
		},
	}

	cmps := append(util.Comparers,
		cmp.Comparer(func(x, y Prefix) bool {
			return x == y
		}),
		cmpopts.IgnoreUnexported(Policy{}),
	)

	// For round-trip testing, we'll normalize the policies before comparing

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test unmarshalling
			policy, err := unmarshalPolicy([]byte(tt.input))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unmarshalling: got %v; want no error", err)
				}
			} else {
				if err == nil {
					t.Fatalf("unmarshalling: got nil; want error %q", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("unmarshalling: got err %v; want error %q", err, tt.wantErr)
				}

				return // Skip the rest of the test if we expected an error
			}

			if diff := cmp.Diff(tt.want, policy, cmps...); diff != "" {
				t.Fatalf("unexpected policy (-want +got):\n%s", diff)
			}

			// Test round-trip marshalling/unmarshalling
			if policy != nil {
				// Marshal the policy back to JSON
				marshalled, err := json.MarshalIndent(policy, "", "  ")
				if err != nil {
					t.Fatalf("marshalling: %v", err)
				}

				// Unmarshal it again
				roundTripped, err := unmarshalPolicy(marshalled)
				if err != nil {
					t.Fatalf("round-trip unmarshalling: %v", err)
				}

				// Add EquateEmpty to handle nil vs empty maps/slices
				roundTripCmps := append(cmps,
					cmpopts.EquateEmpty(),
					cmpopts.IgnoreUnexported(Policy{}),
				)

				// Compare using the enhanced comparers for round-trip testing
				if diff := cmp.Diff(policy, roundTripped, roundTripCmps...); diff != "" {
					t.Fatalf("round trip policy (-original +roundtripped):\n%s", diff)
				}
			}
		})
	}
}

func gp(s string) *Group          { return new(Group(s)) }
func up(s string) *Username       { return new(Username(s)) }
func hp(s string) *Host           { return new(Host(s)) }
func tp(s string) *Tag            { return new(Tag(s)) }
func agp(s string) *AutoGroup     { return new(AutoGroup(s)) }
func mp(pref string) netip.Prefix { return netip.MustParsePrefix(pref) }
func ap(addr string) *netip.Addr  { return new(netip.MustParseAddr(addr)) }
func pp(pref string) *Prefix      { return new(Prefix(mp(pref))) }
func p(pref string) Prefix        { return Prefix(mp(pref)) }

func TestResolvePolicy(t *testing.T) {
	users := map[string]types.User{
		"testuser":   {Model: gorm.Model{ID: 1}, Name: "testuser"},
		"groupuser":  {Model: gorm.Model{ID: 2}, Name: "groupuser"},
		"groupuser1": {Model: gorm.Model{ID: 3}, Name: "groupuser1"},
		"groupuser2": {Model: gorm.Model{ID: 4}, Name: "groupuser2"},
		"notme":      {Model: gorm.Model{ID: 5}, Name: "notme"},
		"testuser2":  {Model: gorm.Model{ID: 6}, Name: "testuser2"},
	}

	tests := []struct {
		name      string
		nodes     types.Nodes
		pol       *Policy
		toResolve Alias
		want      []netip.Prefix
		wantErr   string
	}{
		{
			name:      "prefix",
			toResolve: pp("100.100.101.101/32"),
			want:      []netip.Prefix{mp("100.100.101.101/32")},
		},
		{
			name: "host",
			pol: &Policy{
				Hosts: Hosts{
					"testhost": p("100.100.101.102/32"),
				},
			},
			toResolve: hp("testhost"),
			want:      []netip.Prefix{mp("100.100.101.102/32")},
		},
		{
			name:      "username",
			toResolve: new(Username("testuser@")),
			nodes: types.Nodes{
				// Not matching other user
				{
					User: new(users["notme"]),
					IPv4: ap("100.100.101.1"),
				},
				// Not matching forced tags
				{
					User: new(users["testuser"]),
					Tags: []string{"tag:anything"},
					IPv4: ap("100.100.101.2"),
				},
				// not matching because it's tagged (tags copied from AuthKey)
				{
					User: new(users["testuser"]),
					Tags: []string{"alsotagged"},
					IPv4: ap("100.100.101.3"),
				},
				{
					User: new(users["testuser"]),
					IPv4: ap("100.100.101.103"),
				},
				{
					User: new(users["testuser"]),
					IPv4: ap("100.100.101.104"),
				},
			},
			want: []netip.Prefix{mp("100.100.101.103/32"), mp("100.100.101.104/32")},
		},
		{
			name:      "group",
			toResolve: new(Group("group:testgroup")),
			nodes: types.Nodes{
				// Not matching other user
				{
					User: new(users["notme"]),
					IPv4: ap("100.100.101.4"),
				},
				// Not matching forced tags
				{
					User: new(users["groupuser"]),
					Tags: []string{"tag:anything"},
					IPv4: ap("100.100.101.5"),
				},
				// not matching because it's tagged (tags copied from AuthKey)
				{
					User: new(users["groupuser"]),
					Tags: []string{"tag:alsotagged"},
					IPv4: ap("100.100.101.6"),
				},
				{
					User: new(users["groupuser"]),
					IPv4: ap("100.100.101.203"),
				},
				{
					User: new(users["groupuser"]),
					IPv4: ap("100.100.101.204"),
				},
			},
			pol: &Policy{
				Groups: Groups{
					"group:testgroup":  Usernames{"groupuser"},
					"group:othergroup": Usernames{"notmetoo"},
				},
			},
			want: []netip.Prefix{mp("100.100.101.203/32"), mp("100.100.101.204/32")},
		},
		{
			name:      "tag",
			toResolve: tp("tag:test"),
			nodes: types.Nodes{
				// Not matching other user
				{
					User: new(users["notme"]),
					IPv4: ap("100.100.101.9"),
				},
				// Not matching forced tags
				{
					Tags: []string{"tag:anything"},
					IPv4: ap("100.100.101.10"),
				},
				// not matching pak tag
				{
					AuthKey: &types.PreAuthKey{
						Tags: []string{"tag:alsotagged"},
					},
					IPv4: ap("100.100.101.11"),
				},
				// Not matching forced tags
				{
					Tags: []string{"tag:test"},
					IPv4: ap("100.100.101.234"),
				},
				// matching tag (tags copied from AuthKey during registration)
				{
					Tags: []string{"tag:test"},
					IPv4: ap("100.100.101.239"),
				},
			},
			// TODO(kradalby): tests handling TagOwners + hostinfo
			pol:  &Policy{},
			want: []netip.Prefix{mp("100.100.101.234/32"), mp("100.100.101.239/32")},
		},
		{
			name:      "tag-owned-by-tag-call-child",
			toResolve: tp("tag:smallbrother"),
			pol: &Policy{
				TagOwners: TagOwners{
					Tag("tag:bigbrother"):   {},
					Tag("tag:smallbrother"): {new(Tag("tag:bigbrother"))},
				},
			},
			nodes: types.Nodes{
				// Should not match as we resolve the "child" tag.
				{
					Tags: []string{"tag:bigbrother"},
					IPv4: ap("100.100.101.234"),
				},
				// Should match.
				{
					Tags: []string{"tag:smallbrother"},
					IPv4: ap("100.100.101.239"),
				},
			},
			want: []netip.Prefix{mp("100.100.101.239/32")},
		},
		{
			name:      "tag-owned-by-tag-call-parent",
			toResolve: tp("tag:bigbrother"),
			pol: &Policy{
				TagOwners: TagOwners{
					Tag("tag:bigbrother"):   {},
					Tag("tag:smallbrother"): {new(Tag("tag:bigbrother"))},
				},
			},
			nodes: types.Nodes{
				// Should match - we are resolving "tag:bigbrother" which this node has.
				{
					Tags: []string{"tag:bigbrother"},
					IPv4: ap("100.100.101.234"),
				},
				// Should not match - this node has "tag:smallbrother", not the tag we're resolving.
				{
					Tags: []string{"tag:smallbrother"},
					IPv4: ap("100.100.101.239"),
				},
			},
			want: []netip.Prefix{mp("100.100.101.234/32")},
		},
		{
			name:      "empty-policy",
			toResolve: pp("100.100.101.101/32"),
			pol:       &Policy{},
			want:      []netip.Prefix{mp("100.100.101.101/32")},
		},
		{
			name:      "invalid-host",
			toResolve: hp("invalidhost"),
			pol: &Policy{
				Hosts: Hosts{
					"testhost": p("100.100.101.102/32"),
				},
			},
			wantErr: `resolving host: "invalidhost"`,
		},
		{
			name:      "multiple-groups",
			toResolve: new(Group("group:testgroup")),
			nodes: types.Nodes{
				{
					User: new(users["groupuser1"]),
					IPv4: ap("100.100.101.203"),
				},
				{
					User: new(users["groupuser2"]),
					IPv4: ap("100.100.101.204"),
				},
			},
			pol: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"groupuser1@", "groupuser2@"},
				},
			},
			want: []netip.Prefix{mp("100.100.101.203/32"), mp("100.100.101.204/32")},
		},
		{
			name:      "autogroup-internet",
			toResolve: agp("autogroup:internet"),
			want:      util.TheInternet().Prefixes(),
		},
		{
			name:      "invalid-username",
			toResolve: new(Username("invaliduser@")),
			nodes: types.Nodes{
				{
					User: new(users["testuser"]),
					IPv4: ap("100.100.101.103"),
				},
			},
			wantErr: `user not found: token "invaliduser@"`,
		},
		{
			name:      "invalid-tag",
			toResolve: tp("tag:invalid"),
			nodes: types.Nodes{
				{
					Tags: []string{"tag:test"},
					IPv4: ap("100.100.101.234"),
				},
			},
		},
		{
			name:      "ipv6-address",
			toResolve: pp("fd7a:115c:a1e0::1/128"),
			want:      []netip.Prefix{mp("fd7a:115c:a1e0::1/128")},
		},
		{
			name:      "wildcard-alias",
			toResolve: Wildcard,
			want:      []netip.Prefix{tsaddr.CGNATRange(), tsaddr.TailscaleULARange()},
		},
		{
			name:      "autogroup-member-comprehensive",
			toResolve: new(AutoGroupMember),
			nodes: types.Nodes{
				// Node with no tags (should be included - is a member)
				{
					User: new(users["testuser"]),
					IPv4: ap("100.100.101.1"),
				},
				// Node with single tag (should be excluded - tagged nodes are not members)
				{
					User: new(users["testuser"]),
					Tags: []string{"tag:test"},
					IPv4: ap("100.100.101.2"),
				},
				// Node with multiple tags, all defined in policy (should be excluded)
				{
					User: new(users["testuser"]),
					Tags: []string{"tag:test", "tag:other"},
					IPv4: ap("100.100.101.3"),
				},
				// Node with tag not defined in policy (should be excluded - still tagged)
				{
					User: new(users["testuser"]),
					Tags: []string{"tag:undefined"},
					IPv4: ap("100.100.101.4"),
				},
				// Node with mixed tags - some defined, some not (should be excluded)
				{
					User: new(users["testuser"]),
					Tags: []string{"tag:test", "tag:undefined"},
					IPv4: ap("100.100.101.5"),
				},
				// Another untagged node from different user (should be included)
				{
					User: new(users["testuser2"]),
					IPv4: ap("100.100.101.6"),
				},
			},
			pol: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"):  Owners{new(Username("testuser@"))},
					Tag("tag:other"): Owners{new(Username("testuser@"))},
				},
			},
			want: []netip.Prefix{
				mp("100.100.101.1/32"), // No tags - is a member
				mp("100.100.101.6/32"), // No tags, different user - is a member
			},
		},
		{
			name:      "autogroup-tagged",
			toResolve: new(AutoGroupTagged),
			nodes: types.Nodes{
				// Node with no tags (should be excluded - not tagged)
				{
					User: new(users["testuser"]),
					IPv4: ap("100.100.101.1"),
				},
				// Node with single tag defined in policy (should be included)
				{
					User: new(users["testuser"]),
					Tags: []string{"tag:test"},
					IPv4: ap("100.100.101.2"),
				},
				// Node with multiple tags, all defined in policy (should be included)
				{
					User: new(users["testuser"]),
					Tags: []string{"tag:test", "tag:other"},
					IPv4: ap("100.100.101.3"),
				},
				// Node with tag not defined in policy (should be included - still tagged)
				{
					User: new(users["testuser"]),
					Tags: []string{"tag:undefined"},
					IPv4: ap("100.100.101.4"),
				},
				// Node with mixed tags - some defined, some not (should be included)
				{
					User: new(users["testuser"]),
					Tags: []string{"tag:test", "tag:undefined"},
					IPv4: ap("100.100.101.5"),
				},
				// Another untagged node from different user (should be excluded)
				{
					User: new(users["testuser2"]),
					IPv4: ap("100.100.101.6"),
				},
				// Tagged node from different user (should be included)
				{
					User: new(users["testuser2"]),
					Tags: []string{"tag:server"},
					IPv4: ap("100.100.101.7"),
				},
			},
			pol: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"):   Owners{new(Username("testuser@"))},
					Tag("tag:other"):  Owners{new(Username("testuser@"))},
					Tag("tag:server"): Owners{new(Username("testuser2@"))},
				},
			},
			want: []netip.Prefix{
				mp("100.100.101.2/31"), // .2, .3 consecutive tagged nodes
				mp("100.100.101.4/31"), // .4, .5 consecutive tagged nodes
				mp("100.100.101.7/32"), // Tagged node from different user
			},
		},
		{
			name:      "autogroup-self",
			toResolve: new(AutoGroupSelf),
			nodes: types.Nodes{
				{
					User: new(users["testuser"]),
					IPv4: ap("100.100.101.1"),
				},
				{
					User: new(users["testuser2"]),
					IPv4: ap("100.100.101.2"),
				},
				{
					User: new(users["testuser"]),
					Tags: []string{"tag:test"},
					IPv4: ap("100.100.101.3"),
				},
				{
					User: new(users["testuser2"]),
					Tags: []string{"tag:test"},
					IPv4: ap("100.100.101.4"),
				},
			},
			pol: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Username("testuser@"))},
				},
			},
			wantErr: "autogroup:self requires per-node resolution",
		},
		{
			name:      "autogroup-invalid",
			toResolve: new(AutoGroup("autogroup:invalid")),
			wantErr:   "unknown autogroup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := tt.toResolve.Resolve(tt.pol,
				xmaps.Values(users),
				tt.nodes.ViewSlice())
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("got %v; want no error", err)
				}
			} else {
				if err == nil {
					t.Fatalf("got nil; want error %q", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got err %v; want error %q", err, tt.wantErr)
				}
			}

			var prefs []netip.Prefix

			if ips != nil {
				if p := ips.Prefixes(); len(p) > 0 {
					prefs = p
				}
			}

			if diff := cmp.Diff(tt.want, prefs, util.Comparers...); diff != "" {
				t.Fatalf("unexpected prefs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolveAutoApprovers(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{
			IPv4: ap("100.64.0.1"),
			User: &users[0],
		},
		{
			IPv4: ap("100.64.0.2"),
			User: &users[1],
		},
		{
			IPv4: ap("100.64.0.3"),
			User: &users[2],
		},
		{
			IPv4: ap("100.64.0.4"),
			Tags: []string{"tag:testtag"},
		},
		{
			IPv4: ap("100.64.0.5"),
			Tags: []string{"tag:exittest"},
		},
	}

	tests := []struct {
		name            string
		policy          *Policy
		want            map[netip.Prefix]*netipx.IPSet
		wantAllIPRoutes *netipx.IPSet
		wantErr         bool
	}{
		{
			name: "single-route",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {new(Username("user1@"))},
					},
				},
			},
			want: map[netip.Prefix]*netipx.IPSet{
				mp("10.0.0.0/24"): mustIPSet("100.64.0.1/32"),
			},
			wantAllIPRoutes: nil,
			wantErr:         false,
		},
		{
			name: "multiple-routes",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {new(Username("user1@"))},
						mp("10.0.1.0/24"): {new(Username("user2@"))},
					},
				},
			},
			want: map[netip.Prefix]*netipx.IPSet{
				mp("10.0.0.0/24"): mustIPSet("100.64.0.1/32"),
				mp("10.0.1.0/24"): mustIPSet("100.64.0.2/32"),
			},
			wantAllIPRoutes: nil,
			wantErr:         false,
		},
		{
			name: "exit-node",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					ExitNode: AutoApprovers{new(Username("user1@"))},
				},
			},
			want:            map[netip.Prefix]*netipx.IPSet{},
			wantAllIPRoutes: mustIPSet("100.64.0.1/32"),
			wantErr:         false,
		},
		{
			name: "group-route",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {new(Group("group:testgroup"))},
					},
				},
			},
			want: map[netip.Prefix]*netipx.IPSet{
				mp("10.0.0.0/24"): mustIPSet("100.64.0.1/32", "100.64.0.2/32"),
			},
			wantAllIPRoutes: nil,
			wantErr:         false,
		},
		{
			name: "tag-route-and-exit",
			policy: &Policy{
				TagOwners: TagOwners{
					"tag:testtag": Owners{
						new(Username("user1@")),
						new(Username("user2@")),
					},
					"tag:exittest": Owners{
						new(Group("group:exitgroup")),
					},
				},
				Groups: Groups{
					"group:exitgroup": Usernames{"user2@"},
				},
				AutoApprovers: AutoApproverPolicy{
					ExitNode: AutoApprovers{new(Tag("tag:exittest"))},
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.1.0/24"): {new(Tag("tag:testtag"))},
					},
				},
			},
			want: map[netip.Prefix]*netipx.IPSet{
				mp("10.0.1.0/24"): mustIPSet("100.64.0.4/32"),
			},
			wantAllIPRoutes: mustIPSet("100.64.0.5/32"),
			wantErr:         false,
		},
		{
			name: "mixed-routes-and-exit-nodes",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {new(Group("group:testgroup"))},
						mp("10.0.1.0/24"): {new(Username("user3@"))},
					},
					ExitNode: AutoApprovers{new(Username("user1@"))},
				},
			},
			want: map[netip.Prefix]*netipx.IPSet{
				mp("10.0.0.0/24"): mustIPSet("100.64.0.1/32", "100.64.0.2/32"),
				mp("10.0.1.0/24"): mustIPSet("100.64.0.3/32"),
			},
			wantAllIPRoutes: mustIPSet("100.64.0.1/32"),
			wantErr:         false,
		},
	}

	cmps := append(util.Comparers, cmp.Comparer(ipSetComparer))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotAllIPRoutes, err := resolveAutoApprovers(tt.policy, users, nodes.ViewSlice())
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveAutoApprovers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(tt.want, got, cmps...); diff != "" {
				t.Errorf("resolveAutoApprovers() mismatch (-want +got):\n%s", diff)
			}

			if tt.wantAllIPRoutes != nil {
				if gotAllIPRoutes == nil {
					t.Error("resolveAutoApprovers() expected non-nil allIPRoutes, got nil")
				} else if diff := cmp.Diff(tt.wantAllIPRoutes, gotAllIPRoutes, cmps...); diff != "" {
					t.Errorf("resolveAutoApprovers() allIPRoutes mismatch (-want +got):\n%s", diff)
				}
			} else if gotAllIPRoutes != nil {
				t.Error("resolveAutoApprovers() expected nil allIPRoutes, got non-nil")
			}
		})
	}
}

func TestSSHUsers_NormalUsers(t *testing.T) {
	tests := []struct {
		name  string
		users SSHUsers
		want  []SSHUser
	}{
		{
			name:  "empty users",
			users: SSHUsers{},
			want:  nil,
		},
		{
			name:  "only root",
			users: SSHUsers{"root"},
			want:  nil,
		},
		{
			name:  "only autogroup:nonroot",
			users: SSHUsers{SSHUser(AutoGroupNonRoot)},
			want:  nil,
		},
		{
			name:  "only normal user",
			users: SSHUsers{"ssh-it-user"},
			want:  []SSHUser{"ssh-it-user"},
		},
		{
			name:  "multiple normal users",
			users: SSHUsers{"ubuntu", "admin", "user1"},
			want:  []SSHUser{"ubuntu", "admin", "user1"},
		},
		{
			name:  "mixed users with root",
			users: SSHUsers{"ubuntu", "root", "admin"},
			want:  []SSHUser{"ubuntu", "admin"},
		},
		{
			name:  "mixed users with autogroup:nonroot",
			users: SSHUsers{"ubuntu", SSHUser(AutoGroupNonRoot), "admin"},
			want:  []SSHUser{"ubuntu", "admin"},
		},
		{
			name:  "mixed users with both root and autogroup:nonroot",
			users: SSHUsers{"ubuntu", "root", SSHUser(AutoGroupNonRoot), "admin"},
			want:  []SSHUser{"ubuntu", "admin"},
		},
		{
			name:  "excludes localpart entries",
			users: SSHUsers{"ubuntu", "root", SSHUser(AutoGroupNonRoot), SSHUser("localpart:*@example.com"), "admin"},
			want:  []SSHUser{"ubuntu", "admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.users.NormalUsers()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("NormalUsers() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSSHUsers_ContainsRoot(t *testing.T) {
	tests := []struct {
		name     string
		users    SSHUsers
		expected bool
	}{
		{
			name:     "empty users",
			users:    SSHUsers{},
			expected: false,
		},
		{
			name:     "contains root",
			users:    SSHUsers{"root"},
			expected: true,
		},
		{
			name:     "does not contain root",
			users:    SSHUsers{"ubuntu", "admin"},
			expected: false,
		},
		{
			name:     "contains root among others",
			users:    SSHUsers{"ubuntu", "root", "admin"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.users.ContainsRoot()
			assert.Equal(t, tt.expected, result, "ContainsRoot() should return expected result")
		})
	}
}

func TestSSHUsers_ContainsNonRoot(t *testing.T) {
	tests := []struct {
		name     string
		users    SSHUsers
		expected bool
	}{
		{
			name:     "empty users",
			users:    SSHUsers{},
			expected: false,
		},
		{
			name:     "contains autogroup:nonroot",
			users:    SSHUsers{SSHUser(AutoGroupNonRoot)},
			expected: true,
		},
		{
			name:     "does not contain autogroup:nonroot",
			users:    SSHUsers{"ubuntu", "admin", "root"},
			expected: false,
		},
		{
			name:     "contains autogroup:nonroot among others",
			users:    SSHUsers{"ubuntu", SSHUser(AutoGroupNonRoot), "admin"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.users.ContainsNonRoot()
			assert.Equal(t, tt.expected, result, "ContainsNonRoot() should return expected result")
		})
	}
}

func TestSSHUsers_ContainsLocalpart(t *testing.T) {
	tests := []struct {
		name     string
		users    SSHUsers
		expected bool
	}{
		{
			name:     "empty users",
			users:    SSHUsers{},
			expected: false,
		},
		{
			name:     "contains localpart",
			users:    SSHUsers{SSHUser("localpart:*@example.com")},
			expected: true,
		},
		{
			name:     "does not contain localpart",
			users:    SSHUsers{"ubuntu", "admin", "root"},
			expected: false,
		},
		{
			name:     "contains localpart among others",
			users:    SSHUsers{"ubuntu", SSHUser("localpart:*@example.com"), "admin"},
			expected: true,
		},
		{
			name:     "multiple localpart entries",
			users:    SSHUsers{SSHUser("localpart:*@a.com"), SSHUser("localpart:*@b.com")},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.users.ContainsLocalpart()
			assert.Equal(t, tt.expected, result, "ContainsLocalpart() should return expected result")
		})
	}
}

func TestSSHUsers_LocalpartEntries(t *testing.T) {
	tests := []struct {
		name  string
		users SSHUsers
		want  []SSHUser
	}{
		{
			name:  "empty users",
			users: SSHUsers{},
			want:  nil,
		},
		{
			name:  "no localpart entries",
			users: SSHUsers{"root", "ubuntu", SSHUser(AutoGroupNonRoot)},
			want:  nil,
		},
		{
			name:  "single localpart entry",
			users: SSHUsers{"root", SSHUser("localpart:*@example.com"), "ubuntu"},
			want:  []SSHUser{SSHUser("localpart:*@example.com")},
		},
		{
			name:  "multiple localpart entries",
			users: SSHUsers{SSHUser("localpart:*@a.com"), "root", SSHUser("localpart:*@b.com")},
			want:  []SSHUser{SSHUser("localpart:*@a.com"), SSHUser("localpart:*@b.com")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.users.LocalpartEntries()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("LocalpartEntries() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSSHUser_ParseLocalpart(t *testing.T) {
	tests := []struct {
		name           string
		user           SSHUser
		expectedDomain string
		expectErr      bool
	}{
		{
			name:           "valid localpart",
			user:           SSHUser("localpart:*@example.com"),
			expectedDomain: "example.com",
		},
		{
			name:           "valid localpart with subdomain",
			user:           SSHUser("localpart:*@corp.example.com"),
			expectedDomain: "corp.example.com",
		},
		{
			name:      "missing prefix",
			user:      SSHUser("ubuntu"),
			expectErr: true,
		},
		{
			name:      "missing @ sign",
			user:      SSHUser("localpart:foo"),
			expectErr: true,
		},
		{
			name:      "non-wildcard local part",
			user:      SSHUser("localpart:alice@example.com"),
			expectErr: true,
		},
		{
			name:      "empty domain",
			user:      SSHUser("localpart:*@"),
			expectErr: true,
		},
		{
			name:      "just prefix",
			user:      SSHUser("localpart:"),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, err := tt.user.ParseLocalpart()
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedDomain, domain)
			}
		})
	}
}

func mustIPSet(prefixes ...string) *netipx.IPSet {
	var builder netipx.IPSetBuilder
	for _, p := range prefixes {
		builder.AddPrefix(mp(p))
	}

	ipSet, _ := builder.IPSet()

	return ipSet
}

func ipSetComparer(x, y *netipx.IPSet) bool {
	if x == nil || y == nil {
		return x == y
	}

	return cmp.Equal(x.Prefixes(), y.Prefixes(), util.Comparers...)
}

func TestNodeCanApproveRoute(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{
			IPv4: ap("100.64.0.1"),
			User: &users[0],
		},
		{
			IPv4: ap("100.64.0.2"),
			User: &users[1],
		},
		{
			IPv4: ap("100.64.0.3"),
			User: &users[2],
		},
	}

	tests := []struct {
		name    string
		policy  *Policy
		node    *types.Node
		route   netip.Prefix
		want    bool
		wantErr bool
	}{
		{
			name: "single-route-approval",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {new(Username("user1@"))},
					},
				},
			},
			node:  nodes[0],
			route: mp("10.0.0.0/24"),
			want:  true,
		},
		{
			name: "multiple-routes-approval",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {new(Username("user1@"))},
						mp("10.0.1.0/24"): {new(Username("user2@"))},
					},
				},
			},
			node:  nodes[1],
			route: mp("10.0.1.0/24"),
			want:  true,
		},
		{
			name: "exit-node-approval",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					ExitNode: AutoApprovers{new(Username("user1@"))},
				},
			},
			node:  nodes[0],
			route: tsaddr.AllIPv4(),
			want:  true,
		},
		{
			name: "group-route-approval",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {new(Group("group:testgroup"))},
					},
				},
			},
			node:  nodes[1],
			route: mp("10.0.0.0/24"),
			want:  true,
		},
		{
			name: "mixed-routes-and-exit-nodes-approval",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {new(Group("group:testgroup"))},
						mp("10.0.1.0/24"): {new(Username("user3@"))},
					},
					ExitNode: AutoApprovers{new(Username("user1@"))},
				},
			},
			node:  nodes[0],
			route: tsaddr.AllIPv4(),
			want:  true,
		},
		{
			name: "no-approval",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {new(Username("user2@"))},
					},
				},
			},
			node:  nodes[0],
			route: mp("10.0.0.0/24"),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.policy)
			require.NoError(t, err)

			pm, err := NewPolicyManager(b, users, nodes.ViewSlice())
			require.NoErrorf(t, err, "NewPolicyManager() error = %v", err)

			got := pm.NodeCanApproveRoute(tt.node.View(), tt.route)
			if got != tt.want {
				t.Errorf("NodeCanApproveRoute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveTagOwners(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{
			IPv4: ap("100.64.0.1"),
			User: &users[0],
		},
		{
			IPv4: ap("100.64.0.2"),
			User: &users[1],
		},
		{
			IPv4: ap("100.64.0.3"),
			User: &users[2],
		},
	}

	tests := []struct {
		name    string
		policy  *Policy
		want    map[Tag]*netipx.IPSet
		wantErr bool
	}{
		{
			name: "single-tag-owner",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Username("user1@"))},
				},
			},
			want: map[Tag]*netipx.IPSet{
				Tag("tag:test"): mustIPSet("100.64.0.1/32"),
			},
			wantErr: false,
		},
		{
			name: "multiple-tag-owners",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Username("user1@")), new(Username("user2@"))},
				},
			},
			want: map[Tag]*netipx.IPSet{
				Tag("tag:test"): mustIPSet("100.64.0.1/32", "100.64.0.2/32"),
			},
			wantErr: false,
		},
		{
			name: "group-tag-owner",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Group("group:testgroup"))},
				},
			},
			want: map[Tag]*netipx.IPSet{
				Tag("tag:test"): mustIPSet("100.64.0.1/32", "100.64.0.2/32"),
			},
			wantErr: false,
		},
		{
			name: "tag-owns-tag",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:bigbrother"):   Owners{new(Username("user1@"))},
					Tag("tag:smallbrother"): Owners{new(Tag("tag:bigbrother"))},
				},
			},
			want: map[Tag]*netipx.IPSet{
				Tag("tag:bigbrother"):   mustIPSet("100.64.0.1/32"),
				Tag("tag:smallbrother"): mustIPSet("100.64.0.1/32"),
			},
			wantErr: false,
		},
	}

	cmps := append(util.Comparers, cmp.Comparer(ipSetComparer))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveTagOwners(tt.policy, users, nodes.ViewSlice())
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveTagOwners() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(tt.want, got, cmps...); diff != "" {
				t.Errorf("resolveTagOwners() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNodeCanHaveTag(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{
			IPv4: ap("100.64.0.1"),
			User: &users[0],
		},
		{
			IPv4: ap("100.64.0.2"),
			User: &users[1],
		},
		{
			IPv4: ap("100.64.0.3"),
			User: &users[2],
		},
	}

	tests := []struct {
		name    string
		policy  *Policy
		node    *types.Node
		tag     string
		want    bool
		wantErr string
	}{
		{
			name: "single-tag-owner",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Username("user1@"))},
				},
			},
			node: nodes[0],
			tag:  "tag:test",
			want: true,
		},
		{
			name: "multiple-tag-owners",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Username("user1@")), new(Username("user2@"))},
				},
			},
			node: nodes[1],
			tag:  "tag:test",
			want: true,
		},
		{
			name: "group-tag-owner",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Group("group:testgroup"))},
				},
			},
			node: nodes[1],
			tag:  "tag:test",
			want: true,
		},
		{
			name: "invalid-group",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"invalid"},
				},
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Group("group:testgroup"))},
				},
			},
			node:    nodes[0],
			tag:     "tag:test",
			want:    false,
			wantErr: "username must contain @",
		},
		{
			name: "node-cannot-have-tag",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Username("user2@"))},
				},
			},
			node: nodes[0],
			tag:  "tag:test",
			want: false,
		},
		{
			name: "node-with-unauthorized-tag-different-user",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:prod"): Owners{new(Username("user1@"))},
				},
			},
			node: nodes[2], // user3's node
			tag:  "tag:prod",
			want: false,
		},
		{
			name: "node-with-multiple-tags-one-unauthorized",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:web"):      Owners{new(Username("user1@"))},
					Tag("tag:database"): Owners{new(Username("user2@"))},
				},
			},
			node: nodes[0], // user1's node
			tag:  "tag:database",
			want: false, // user1 cannot have tag:database (owned by user2)
		},
		{
			name: "empty-tagowners-map",
			policy: &Policy{
				TagOwners: TagOwners{},
			},
			node: nodes[0],
			tag:  "tag:test",
			want: false, // No one can have tags if tagOwners is empty
		},
		{
			name: "tag-not-in-tagowners",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:prod"): Owners{new(Username("user1@"))},
				},
			},
			node: nodes[0],
			tag:  "tag:dev", // This tag is not defined in tagOwners
			want: false,
		},
		// Test cases for nodes without IPs (new registration scenario)
		// These test the user-based fallback in NodeCanHaveTag
		{
			name: "node-without-ip-user-owns-tag",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Username("user1@"))},
				},
			},
			node: &types.Node{
				// No IPv4 or IPv6 - simulates new node registration
				User:   &users[0],
				UserID: new(users[0].ID),
			},
			tag:  "tag:test",
			want: true, // Should succeed via user-based fallback
		},
		{
			name: "node-without-ip-user-does-not-own-tag",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Username("user2@"))},
				},
			},
			node: &types.Node{
				// No IPv4 or IPv6 - simulates new node registration
				User:   &users[0], // user1, but tag owned by user2
				UserID: new(users[0].ID),
			},
			tag:  "tag:test",
			want: false, // user1 does not own tag:test
		},
		{
			name: "node-without-ip-group-owns-tag",
			policy: &Policy{
				Groups: Groups{
					"group:admins": Usernames{"user1@", "user2@"},
				},
				TagOwners: TagOwners{
					Tag("tag:admin"): Owners{new(Group("group:admins"))},
				},
			},
			node: &types.Node{
				// No IPv4 or IPv6 - simulates new node registration
				User:   &users[1], // user2 is in group:admins
				UserID: new(users[1].ID),
			},
			tag:  "tag:admin",
			want: true, // Should succeed via group membership
		},
		{
			name: "node-without-ip-not-in-group",
			policy: &Policy{
				Groups: Groups{
					"group:admins": Usernames{"user1@"},
				},
				TagOwners: TagOwners{
					Tag("tag:admin"): Owners{new(Group("group:admins"))},
				},
			},
			node: &types.Node{
				// No IPv4 or IPv6 - simulates new node registration
				User:   &users[1], // user2 is NOT in group:admins
				UserID: new(users[1].ID),
			},
			tag:  "tag:admin",
			want: false, // user2 is not in group:admins
		},
		{
			name: "node-without-ip-no-user",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{new(Username("user1@"))},
				},
			},
			node: &types.Node{
				// No IPv4, IPv6, or User - edge case
			},
			tag:  "tag:test",
			want: false, // No user means can't authorize via user-based fallback
		},
		{
			name: "node-without-ip-mixed-owners-user-match",
			policy: &Policy{
				Groups: Groups{
					"group:ops": Usernames{"user3@"},
				},
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{
						new(Username("user1@")),
						new(Group("group:ops")),
					},
				},
			},
			node: &types.Node{
				User:   &users[0], // user1 directly owns the tag
				UserID: new(users[0].ID),
			},
			tag:  "tag:server",
			want: true,
		},
		{
			name: "node-without-ip-mixed-owners-group-match",
			policy: &Policy{
				Groups: Groups{
					"group:ops": Usernames{"user3@"},
				},
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{
						new(Username("user1@")),
						new(Group("group:ops")),
					},
				},
			},
			node: &types.Node{
				User:   &users[2], // user3 is in group:ops
				UserID: new(users[2].ID),
			},
			tag:  "tag:server",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.policy)
			require.NoError(t, err)

			pm, err := NewPolicyManager(b, users, nodes.ViewSlice())
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)

			got := pm.NodeCanHaveTag(tt.node.View(), tt.tag)
			if got != tt.want {
				t.Errorf("NodeCanHaveTag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserMatchesOwner(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	tests := []struct {
		name   string
		policy *Policy
		user   types.User
		owner  Owner
		want   bool
	}{
		{
			name:   "username-match",
			policy: &Policy{},
			user:   users[0],
			owner:  new(Username("user1@")),
			want:   true,
		},
		{
			name:   "username-no-match",
			policy: &Policy{},
			user:   users[0],
			owner:  new(Username("user2@")),
			want:   false,
		},
		{
			name: "group-match",
			policy: &Policy{
				Groups: Groups{
					"group:admins": Usernames{"user1@", "user2@"},
				},
			},
			user:  users[1], // user2 is in group:admins
			owner: new(Group("group:admins")),
			want:  true,
		},
		{
			name: "group-no-match",
			policy: &Policy{
				Groups: Groups{
					"group:admins": Usernames{"user1@"},
				},
			},
			user:  users[1], // user2 is NOT in group:admins
			owner: new(Group("group:admins")),
			want:  false,
		},
		{
			name: "group-not-defined",
			policy: &Policy{
				Groups: Groups{},
			},
			user:  users[0],
			owner: new(Group("group:undefined")),
			want:  false,
		},
		{
			name:   "nil-username-owner",
			policy: &Policy{},
			user:   users[0],
			owner:  (*Username)(nil),
			want:   false,
		},
		{
			name:   "nil-group-owner",
			policy: &Policy{},
			user:   users[0],
			owner:  (*Group)(nil),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal PolicyManager for testing
			// We need nodes with IPs to initialize the tagOwnerMap
			nodes := types.Nodes{
				{
					IPv4: ap("100.64.0.1"),
					User: &users[0],
				},
			}

			b, err := json.Marshal(tt.policy)
			require.NoError(t, err)

			pm, err := NewPolicyManager(b, users, nodes.ViewSlice())
			require.NoError(t, err)

			got := pm.userMatchesOwner(tt.user.View(), tt.owner)
			if got != tt.want {
				t.Errorf("userMatchesOwner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestACL_UnmarshalJSON_WithCommentFields(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ACL
		wantErr  bool
	}{
		{
			name: "basic ACL with comment fields",
			input: `{
				"#comment": "This is a comment",
				"action": "accept",
				"proto": "tcp",
				"src": ["user1@example.com"],
				"dst": ["tag:server:80"]
			}`,
			expected: ACL{
				Action:   "accept",
				Protocol: "tcp",
				Sources:  []Alias{mustParseAlias("user1@example.com")},
				Destinations: []AliasWithPorts{
					{
						Alias: mustParseAlias("tag:server"),
						Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple comment fields",
			input: `{
				"#description": "Allow access to web servers",
				"#note": "Created by admin",
				"#created_date": "2024-01-15",
				"action": "accept",
				"proto": "tcp",
				"src": ["group:developers"],
				"dst": ["10.0.0.0/24:443"]
			}`,
			expected: ACL{
				Action:   "accept",
				Protocol: "tcp",
				Sources:  []Alias{mustParseAlias("group:developers")},
				Destinations: []AliasWithPorts{
					{
						Alias: mustParseAlias("10.0.0.0/24"),
						Ports: []tailcfg.PortRange{{First: 443, Last: 443}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "comment field with complex object value",
			input: `{
				"#metadata": {
					"description": "Complex comment object",
					"tags": ["web", "production"],
					"created_by": "admin"
				},
				"action": "accept",
				"proto": "udp",
				"src": ["*"],
				"dst": ["autogroup:internet:53"]
			}`,
			expected: ACL{
				Action:   ActionAccept,
				Protocol: "udp",
				Sources:  []Alias{Wildcard},
				Destinations: []AliasWithPorts{
					{
						Alias: mustParseAlias("autogroup:internet"),
						Ports: []tailcfg.PortRange{{First: 53, Last: 53}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid action should fail",
			input: `{
				"action": "deny",
				"proto": "tcp",
				"src": ["*"],
				"dst": ["*:*"]
			}`,
			wantErr: true,
		},
		{
			name: "no comment fields",
			input: `{
				"action": "accept",
				"proto": "icmp",
				"src": ["tag:client"],
				"dst": ["tag:server:*"]
			}`,
			expected: ACL{
				Action:   ActionAccept,
				Protocol: "icmp",
				Sources:  []Alias{mustParseAlias("tag:client")},
				Destinations: []AliasWithPorts{
					{
						Alias: mustParseAlias("tag:server"),
						Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "only comment fields",
			input: `{
				"#comment": "This rule is disabled",
				"#reason": "Temporary disable for maintenance"
			}`,
			expected: ACL{
				Action:       Action(""),
				Protocol:     Protocol(""),
				Sources:      nil,
				Destinations: nil,
			},
			wantErr: false,
		},
		{
			name: "invalid JSON",
			input: `{
				"#comment": "This is a comment",
				"action": "accept",
				"proto": "tcp"
				"src": ["invalid json"]
			}`,
			wantErr: true,
		},
		{
			name: "invalid field after comment filtering",
			input: `{
				"#comment": "This is a comment",
				"action": "accept",
				"proto": "tcp",
				"src": ["user1@example.com"],
				"dst": ["invalid-destination"]
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var acl ACL

			err := json.Unmarshal([]byte(tt.input), &acl)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected.Action, acl.Action)
			assert.Equal(t, tt.expected.Protocol, acl.Protocol)
			assert.Len(t, acl.Sources, len(tt.expected.Sources))
			assert.Len(t, acl.Destinations, len(tt.expected.Destinations))

			// Compare sources
			for i, expectedSrc := range tt.expected.Sources {
				if i < len(acl.Sources) {
					assert.Equal(t, expectedSrc, acl.Sources[i])
				}
			}

			// Compare destinations
			for i, expectedDst := range tt.expected.Destinations {
				if i < len(acl.Destinations) {
					assert.Equal(t, expectedDst.Alias, acl.Destinations[i].Alias)
					assert.Equal(t, expectedDst.Ports, acl.Destinations[i].Ports)
				}
			}
		})
	}
}

func TestACL_UnmarshalJSON_Roundtrip(t *testing.T) {
	// Test that marshaling and unmarshaling preserves data (excluding comments)
	original := ACL{
		Action:   "accept",
		Protocol: "tcp",
		Sources:  []Alias{mustParseAlias("group:admins")},
		Destinations: []AliasWithPorts{
			{
				Alias: mustParseAlias("tag:server"),
				Ports: []tailcfg.PortRange{{First: 22, Last: 22}, {First: 80, Last: 80}},
			},
		},
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var unmarshaled ACL

	err = json.Unmarshal(jsonBytes, &unmarshaled)
	require.NoError(t, err)

	// Should be equal
	assert.Equal(t, original.Action, unmarshaled.Action)
	assert.Equal(t, original.Protocol, unmarshaled.Protocol)
	assert.Len(t, unmarshaled.Sources, len(original.Sources))
	assert.Len(t, unmarshaled.Destinations, len(original.Destinations))
}

func TestACL_UnmarshalJSON_PolicyIntegration(t *testing.T) {
	// Test that ACL unmarshaling works within a Policy context
	policyJSON := `{
		"groups": {
			"group:developers": ["user1@example.com", "user2@example.com"]
		},
		"tagOwners": {
			"tag:server": ["group:developers"]
		},
		"acls": [
			{
				"#description": "Allow developers to access servers",
				"#priority": "high",
				"action": "accept",
				"proto": "tcp",
				"src": ["group:developers"],
				"dst": ["tag:server:22,80,443"]
			},
			{
				"#note": "Allow all other traffic",
				"action": "accept",
				"proto": "tcp",
				"src": ["*"],
				"dst": ["*:*"]
			}
		]
	}`

	policy, err := unmarshalPolicy([]byte(policyJSON))
	require.NoError(t, err)
	require.NotNil(t, policy)

	// Check that ACLs were parsed correctly
	require.Len(t, policy.ACLs, 2)

	// First ACL
	acl1 := policy.ACLs[0]
	assert.Equal(t, ActionAccept, acl1.Action)
	assert.Equal(t, Protocol("tcp"), acl1.Protocol)
	require.Len(t, acl1.Sources, 1)
	require.Len(t, acl1.Destinations, 1)

	// Second ACL
	acl2 := policy.ACLs[1]
	assert.Equal(t, ActionAccept, acl2.Action)
	assert.Equal(t, Protocol("tcp"), acl2.Protocol)
	require.Len(t, acl2.Sources, 1)
	require.Len(t, acl2.Destinations, 1)
}

func TestACL_UnmarshalJSON_InvalidAction(t *testing.T) {
	// Test that invalid actions are rejected
	policyJSON := `{
		"acls": [
			{
				"action": "deny",
				"proto": "tcp",
				"src": ["*"],
				"dst": ["*:*"]
			}
		]
	}`

	_, err := unmarshalPolicy([]byte(policyJSON))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid ACL action: "deny"`)
}

// Helper function to parse aliases for testing.
func mustParseAlias(s string) Alias {
	alias, err := parseAlias(s)
	if err != nil {
		panic(err)
	}

	return alias
}

func TestFlattenTagOwners(t *testing.T) {
	tests := []struct {
		name    string
		input   TagOwners
		want    TagOwners
		wantErr string
	}{
		{
			name: "tag-owns-tag",
			input: TagOwners{
				Tag("tag:bigbrother"):   Owners{new(Group("group:user1"))},
				Tag("tag:smallbrother"): Owners{new(Tag("tag:bigbrother"))},
			},
			want: TagOwners{
				Tag("tag:bigbrother"):   Owners{new(Group("group:user1"))},
				Tag("tag:smallbrother"): Owners{new(Group("group:user1"))},
			},
			wantErr: "",
		},
		{
			name: "circular-reference",
			input: TagOwners{
				Tag("tag:a"): Owners{new(Tag("tag:b"))},
				Tag("tag:b"): Owners{new(Tag("tag:a"))},
			},
			want:    nil,
			wantErr: "circular reference detected: tag:a -> tag:b",
		},
		{
			name: "mixed-owners",
			input: TagOwners{
				Tag("tag:x"): Owners{new(Username("user1@")), new(Tag("tag:y"))},
				Tag("tag:y"): Owners{new(Username("user2@"))},
			},
			want: TagOwners{
				Tag("tag:x"): Owners{new(Username("user1@")), new(Username("user2@"))},
				Tag("tag:y"): Owners{new(Username("user2@"))},
			},
			wantErr: "",
		},
		{
			name: "mixed-dupe-owners",
			input: TagOwners{
				Tag("tag:x"): Owners{new(Username("user1@")), new(Tag("tag:y"))},
				Tag("tag:y"): Owners{new(Username("user1@"))},
			},
			want: TagOwners{
				Tag("tag:x"): Owners{new(Username("user1@"))},
				Tag("tag:y"): Owners{new(Username("user1@"))},
			},
			wantErr: "",
		},
		{
			name: "no-tag-owners",
			input: TagOwners{
				Tag("tag:solo"): Owners{new(Username("user1@"))},
			},
			want: TagOwners{
				Tag("tag:solo"): Owners{new(Username("user1@"))},
			},
			wantErr: "",
		},
		{
			name: "tag-long-owner-chain",
			input: TagOwners{
				Tag("tag:a"): Owners{new(Group("group:user1"))},
				Tag("tag:b"): Owners{new(Tag("tag:a"))},
				Tag("tag:c"): Owners{new(Tag("tag:b"))},
				Tag("tag:d"): Owners{new(Tag("tag:c"))},
				Tag("tag:e"): Owners{new(Tag("tag:d"))},
				Tag("tag:f"): Owners{new(Tag("tag:e"))},
				Tag("tag:g"): Owners{new(Tag("tag:f"))},
			},
			want: TagOwners{
				Tag("tag:a"): Owners{new(Group("group:user1"))},
				Tag("tag:b"): Owners{new(Group("group:user1"))},
				Tag("tag:c"): Owners{new(Group("group:user1"))},
				Tag("tag:d"): Owners{new(Group("group:user1"))},
				Tag("tag:e"): Owners{new(Group("group:user1"))},
				Tag("tag:f"): Owners{new(Group("group:user1"))},
				Tag("tag:g"): Owners{new(Group("group:user1"))},
			},
			wantErr: "",
		},
		{
			name: "tag-long-circular-chain",
			input: TagOwners{
				Tag("tag:a"): Owners{new(Tag("tag:g"))},
				Tag("tag:b"): Owners{new(Tag("tag:a"))},
				Tag("tag:c"): Owners{new(Tag("tag:b"))},
				Tag("tag:d"): Owners{new(Tag("tag:c"))},
				Tag("tag:e"): Owners{new(Tag("tag:d"))},
				Tag("tag:f"): Owners{new(Tag("tag:e"))},
				Tag("tag:g"): Owners{new(Tag("tag:f"))},
			},
			wantErr: "circular reference detected: tag:a -> tag:b -> tag:c -> tag:d -> tag:e -> tag:f -> tag:g",
		},
		{
			name: "undefined-tag-reference",
			input: TagOwners{
				Tag("tag:a"): Owners{new(Tag("tag:nonexistent"))},
			},
			wantErr: `tag "tag:a" references undefined tag "tag:nonexistent"`,
		},
		{
			name: "tag-with-empty-owners-is-valid",
			input: TagOwners{
				Tag("tag:a"): Owners{new(Tag("tag:b"))},
				Tag("tag:b"): Owners{}, // empty owners but exists
			},
			want: TagOwners{
				Tag("tag:a"): nil,
				Tag("tag:b"): nil,
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := flattenTagOwners(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("flattenTagOwners() expected error %q, got nil", tt.wantErr)
				}

				if err.Error() != tt.wantErr {
					t.Fatalf("flattenTagOwners() expected error %q, got %q", tt.wantErr, err.Error())
				}

				return
			}

			if err != nil {
				t.Fatalf("flattenTagOwners() unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("flattenTagOwners() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSSHCheckPeriodUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *SSHCheckPeriod
		wantErr bool
	}{
		{
			name:  "always",
			input: `"always"`,
			want:  &SSHCheckPeriod{Always: true},
		},
		{
			name:  "1h",
			input: `"1h"`,
			want:  &SSHCheckPeriod{Duration: time.Hour},
		},
		{
			name:  "30m",
			input: `"30m"`,
			want:  &SSHCheckPeriod{Duration: 30 * time.Minute},
		},
		{
			name:  "168h",
			input: `"168h"`,
			want:  &SSHCheckPeriod{Duration: 168 * time.Hour},
		},
		{
			name:    "invalid",
			input:   `"notaduration"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got SSHCheckPeriod

			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, *tt.want, got)
		})
	}
}

func TestSSHCheckPeriodRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input SSHCheckPeriod
	}{
		{
			name:  "always",
			input: SSHCheckPeriod{Always: true},
		},
		{
			name:  "2h",
			input: SSHCheckPeriod{Duration: 2 * time.Hour},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.input)
			require.NoError(t, err)

			var got SSHCheckPeriod

			err = json.Unmarshal(data, &got)
			require.NoError(t, err)

			assert.Equal(t, tt.input, got)
		})
	}
}

func TestSSHCheckPeriodNilInSSH(t *testing.T) {
	input := `{
		"action": "check",
		"src": ["user@"],
		"dst": ["autogroup:member"],
		"users": ["root"]
	}`

	var ssh SSH

	err := json.Unmarshal([]byte(input), &ssh)
	require.NoError(t, err)
	assert.Nil(t, ssh.CheckPeriod)
}

func TestSSHCheckPeriodValidate(t *testing.T) {
	tests := []struct {
		name    string
		period  SSHCheckPeriod
		wantErr error
	}{
		{
			name:   "always is valid",
			period: SSHCheckPeriod{Always: true},
		},
		{
			name:   "1m minimum valid",
			period: SSHCheckPeriod{Duration: time.Minute},
		},
		{
			name:   "168h maximum valid",
			period: SSHCheckPeriod{Duration: 168 * time.Hour},
		},
		{
			name:    "30s below minimum",
			period:  SSHCheckPeriod{Duration: 30 * time.Second},
			wantErr: ErrSSHCheckPeriodBelowMin,
		},
		{
			name:    "169h above maximum",
			period:  SSHCheckPeriod{Duration: 169 * time.Hour},
			wantErr: ErrSSHCheckPeriodAboveMax,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.period.Validate()
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestSSHCheckPeriodPolicyValidation(t *testing.T) {
	tests := []struct {
		name    string
		ssh     SSH
		wantErr error
	}{
		{
			name: "check with nil period is valid",
			ssh: SSH{
				Action:       SSHActionCheck,
				Sources:      SSHSrcAliases{up("user@")},
				Destinations: SSHDstAliases{agp("autogroup:member")},
				Users:        SSHUsers{"root"},
			},
		},
		{
			name: "check with always is valid",
			ssh: SSH{
				Action:       SSHActionCheck,
				Sources:      SSHSrcAliases{up("user@")},
				Destinations: SSHDstAliases{agp("autogroup:member")},
				Users:        SSHUsers{"root"},
				CheckPeriod:  &SSHCheckPeriod{Always: true},
			},
		},
		{
			name: "check with 1h is valid",
			ssh: SSH{
				Action:       SSHActionCheck,
				Sources:      SSHSrcAliases{up("user@")},
				Destinations: SSHDstAliases{agp("autogroup:member")},
				Users:        SSHUsers{"root"},
				CheckPeriod:  &SSHCheckPeriod{Duration: time.Hour},
			},
		},
		{
			name: "accept with checkPeriod is invalid",
			ssh: SSH{
				Action:       SSHActionAccept,
				Sources:      SSHSrcAliases{up("user@")},
				Destinations: SSHDstAliases{agp("autogroup:member")},
				Users:        SSHUsers{"root"},
				CheckPeriod:  &SSHCheckPeriod{Duration: time.Hour},
			},
			wantErr: ErrSSHCheckPeriodOnNonCheck,
		},
		{
			name: "check with 30s is invalid",
			ssh: SSH{
				Action:       SSHActionCheck,
				Sources:      SSHSrcAliases{up("user@")},
				Destinations: SSHDstAliases{agp("autogroup:member")},
				Users:        SSHUsers{"root"},
				CheckPeriod:  &SSHCheckPeriod{Duration: 30 * time.Second},
			},
			wantErr: ErrSSHCheckPeriodBelowMin,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := &Policy{SSHs: []SSH{tt.ssh}}
			err := pol.validate()

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}
