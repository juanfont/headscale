package main

import (
	"slices"
	"testing"
)

func TestActionRefMatch(t *testing.T) {
	tests := []struct {
		name             string
		line             string
		owner, repo, sub string
		ref              string
		match            bool
	}{
		{
			name:  "release tag",
			line:  "      - uses: actions/checkout@v7.0.1\n",
			owner: "actions", repo: "checkout",
			ref:   "v7.0.1",
			match: true,
		},
		{
			name:  "action in a subdirectory",
			line:  "        uses: mitchellh/vouch/action/check-pr@v1.5.0\n",
			owner: "mitchellh", repo: "vouch", sub: "/action/check-pr",
			ref:   "v1.5.0",
			match: true,
		},
		{
			name:  "branch",
			line:  "        uses: self-actuated/block-with-tmux@master\n",
			owner: "self-actuated", repo: "block-with-tmux",
			ref:   "master",
			match: true,
		},
		{
			name: "local reusable workflow",
			line: "    uses: ./.github/workflows/integration-test-template.yml\n",
		},
		{
			name: "same-repo action",
			line: "        uses: $/.github/actions/headscale-up\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := actionRef.FindStringSubmatch(test.line)
			if (m != nil) != test.match {
				t.Fatalf("match = %v, want %v", m != nil, test.match)
			}

			if m == nil {
				return
			}

			for i, want := range map[int]string{2: test.owner, 3: test.repo, 4: test.sub, 5: test.ref} {
				if m[i] != want {
					t.Errorf("group %d = %q, want %q", i, m[i], want)
				}
			}
		})
	}
}

func TestRewriteActions(t *testing.T) {
	const content = `    steps:
      - uses: actions/checkout@v7.0.1
        with:
          persist-credentials: false
      - uses: mitchellh/vouch/action/check-pr@v1.5.0
      - uses: self-actuated/block-with-tmux@master
      - uses: $/.github/actions/headscale-up
`

	const want = `    steps:
      - uses: actions/checkout@v7.1.0
        with:
          persist-credentials: false
      - uses: mitchellh/vouch/action/check-pr@v1.5.0
      - uses: self-actuated/block-with-tmux@master
      - uses: $/.github/actions/headscale-up
`

	// Pre-resolved, so the test needs no network; the branch is never looked up.
	latest := map[string]string{"actions/checkout": "v7.1.0", "mitchellh/vouch": "v1.5.0"}
	moved := map[string]string{}

	got, err := rewriteActions(t.Context(), content, latest, moved)
	if err != nil {
		t.Fatal(err)
	}

	if got != want {
		t.Errorf("rewrite =\n%s\nwant\n%s", got, want)
	}

	if len(moved) != 1 || moved["actions/checkout"] != "actions/checkout v7.0.1 -> v7.1.0" {
		t.Errorf("moved = %v", moved)
	}
}

func TestLockMoves(t *testing.T) {
	const before = `version: 'v0.0.3'
dependencies:
    'actions/checkout@v7.0.1':
        ref: 'v7.0.1'
        commit: 'sha1-3d3c42e5aac5ba805825da76410c181273ba90b1'
    'self-actuated/block-with-tmux@master':
        ref: 'master'
        commit: 'sha1-4d7a7ea0000000000000000000000000000000000'
    'mic92/hestia@v3.1.0':
        ref: 'v3.1.0'
        commit: 'sha1-dfed9ced335d28978ba74e513939a10db1f71025'
`

	const after = `version: 'v0.0.3'
dependencies:
    'actions/checkout@v7.1.0':
        ref: 'v7.1.0'
        commit: 'sha1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    'self-actuated/block-with-tmux@master':
        ref: 'master'
        commit: 'sha1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    'mic92/hestia@v3.1.0':
        ref: 'v3.1.0'
        commit: 'sha1-dfed9ced335d28978ba74e513939a10db1f71025'
`

	got, err := lockMoves(before, after)
	if err != nil {
		t.Fatal(err)
	}

	// The checkout tag move is a new entry, not a move; only the branch counts.
	want := []string{"self-actuated/block-with-tmux@master 4d7a7ea -> bbbbbbb"}
	if !slices.Equal(got, want) {
		t.Errorf("lockMoves = %q, want %q", got, want)
	}
}

func TestIsVersionRef(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: "v6.0.1", want: true},
		{in: "v3.22", want: true},
		{in: "main"},
		{in: "master"},
		{in: "validate"},
		{in: "v"},
	}

	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			if got := isVersionRef(test.in); got != test.want {
				t.Errorf("isVersionRef(%q) = %v, want %v", test.in, got, test.want)
			}
		})
	}
}
