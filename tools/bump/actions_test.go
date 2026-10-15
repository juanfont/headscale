package main

import "testing"

func TestActionPinMatch(t *testing.T) {
	tests := []struct {
		name             string
		line             string
		owner, repo, sub string
		sha, ref         string
		match            bool
	}{
		{
			name:  "sha pinned with version comment",
			line:  "      - uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1\n",
			owner: "actions", repo: "checkout",
			sha:   "8e8c483db84b4bee98b60c0593521ed34d9990e8",
			ref:   "v6.0.1",
			match: true,
		},
		{
			name:  "branch comment",
			line:  "      - uses: NixOS/nix-installer-action@6b8548fe06acfb0155a50ab5d561accb215764cc # main\n",
			owner: "NixOS", repo: "nix-installer-action",
			sha:   "6b8548fe06acfb0155a50ab5d561accb215764cc",
			ref:   "main",
			match: true,
		},
		{
			// No SHA to replace and no comment to correct; leave it alone
			// rather than silently changing how it is pinned.
			name: "unpinned branch reference",
			line: "        uses: alexellis/setup-sshd-actor@master\n",
		},
		{
			name: "local reusable workflow",
			line: "    uses: ./.github/workflows/integration-test-template.yml\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := actionPin.FindStringSubmatch(test.line)
			if (m != nil) != test.match {
				t.Fatalf("match = %v, want %v", m != nil, test.match)
			}

			if m == nil {
				return
			}

			for i, want := range map[int]string{2: test.owner, 3: test.repo, 4: test.sub, 5: test.sha, 7: test.ref} {
				if m[i] != want {
					t.Errorf("group %d = %q, want %q", i, m[i], want)
				}
			}
		})
	}
}

func TestActionPinRewrite(t *testing.T) {
	const line = "      - uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1\n"

	m := actionPin.FindStringSubmatch(line)
	got := m[1] + m[2] + "/" + m[3] + m[4] + "@" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + m[6] + "v7.0.0"

	const want = "uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v7.0.0"
	if got != want {
		t.Errorf("rewrite = %q, want %q", got, want)
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
