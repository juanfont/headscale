package main

import "testing"

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"--auth-key=file:/tmp/headscale-dev-1/authkey": "--auth-key=file:/tmp/headscale-dev-1/authkey",
		"--auth-key=file:/tmp/my dir/authkey":          "'--auth-key=file:/tmp/my dir/authkey'",
		"/tmp/it's/config.yaml":                        `'/tmp/it'\''s/config.yaml'`,
		"/tmp/$HOME/config.yaml":                       "'/tmp/$HOME/config.yaml'",
		`/tmp/"q"/x`:                                   `'/tmp/"q"/x'`,
		"":                                             "''",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
