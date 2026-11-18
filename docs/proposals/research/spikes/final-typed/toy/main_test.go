package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestToy(t *testing.T) {
	for _, tc := range []struct {
		line string
		code int
		want string
	}{
		{"net ping alpha", 0, "ping alpha (10.0.0.1) n=3 wait=1s from=invalid IP/false level=mid via=[] labels=[] verbose=false\n"},
		{"net p beta -n 5 --wait 250ms --from ::1 --level high --via alpha,beta -l a -l b -v", 0, "ping beta (10.0.0.2) n=5 wait=250ms from=::1/true level=high via=[{alpha 10.0.0.1} {beta 10.0.0.2}] labels=[\"a\" \"b\"] verbose=true\n"},
		{"net ping gamma --store lab", 0, "ping gamma (fd00::3) n=3 wait=1s from=invalid IP/false level=mid via=[] labels=[] verbose=false\n"},
		{"net ping gamma", 2, "toy: argument host: \"gamma\": no such host\n"},
		{"net ping alpha --via beta,nobody", 2, "toy: flag --via: \"beta,nobody\": no such host\n"},
		{"net ping alpha --wait 5", 2, "toy: flag --wait: \"5\": time: missing unit in duration \"5\"\n"},
		{"net ping alpha --from here", 2, "toy: flag --from: \"here\": ParseAddr(\"here\"): unable to parse IP\n"},
		{"net ping alpha --level loud", 2, "toy: flag --level: \"loud\": want one of low, mid, high\n"},
		{"net ping alpha -n 1 -n 2", 2, "toy: flag --count is given more than once\n"},
		{"net ping", 2, "toy: wrong number of arguments for \"net ping\"\n"},
		{"net ping nobody --bogus", 2, "toy: unknown flag --bogus for \"net ping\"\n"}, // the mistake on the line comes before any lookup
		{"net", 2, "toy: toy net: a command is needed\n"},
		{"net ping -h", 0, "Ping a host\n\n  toy net ping <host>\n  <host>  The host to ping\n  -n, --count int              How many times (default 3)\n  --wait duration              Time between two pings (default 1s)\n  --from addr                  Source address\n  --level level                How much to print (default mid)\n  --via host                   Hosts to go through\n  -l, --label string           A label; may be given more than once\n  --store path                 The store of hosts (default hosts)\n  -v, --verbose                Say more\n  -h, --help                   Show help\n"},
		{"--help", 0, "A toy\n\n  toy\n  toy net                      Network tools\n  toy completion <shell>       Write a completion script\n  -h, --help                   Show help\n"},
		{"__complete net ping --store lab ", 0, "gamma\n:4\n"},
		{"__complete net ping ", 0, "alpha\nbeta\n:4\n"},
		{"__complete net ping alpha --level ", 0, "low\nmid\nhigh\n:4\n"},
		{"__complete net ping alpha --via alpha,b", 0, "alpha,beta\n:6\n"},
		{"__complete net ping alpha --store ", 0, ":0\n"},
	} {
		var out, errw bytes.Buffer
		code := run(strings.Split(tc.line, " "), &out, &errw)
		if got := out.String() + errw.String(); code != tc.code || got != tc.want {
			t.Errorf("%q: exit %d\n got %q\nwant %q", tc.line, code, got, tc.want)
		}
	}
	var out, errw bytes.Buffer
	if run([]string{"completion", "bash"}, &out, &errw) != 0 || !strings.Contains(out.String(), "toy") {
		t.Errorf("completion bash: %s", errw.String())
	}
}

// TestNoHeadscale: the library and this program name nothing of Headscale.
func TestNoHeadscale(t *testing.T) {
	out, _ := exec.Command("grep", "-rilE", "headscale|tailscale|preauth|hskey", "--include=*.go", "../cmdline", ".").Output()
	for _, f := range strings.Fields(string(out)) {
		if f != "./main_test.go" && f != "./main.go" {
			t.Errorf("%s names Headscale", f)
		}
	}
	if b, _ := exec.Command("grep", "-ciE", "tailscale|preauth|hskey", "main.go").Output(); strings.TrimSpace(string(b)) != "0" {
		t.Error("main.go names a Headscale concept")
	}
	deps, err := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range strings.Fields(string(deps)) {
		if strings.Contains(d, "headscale") || strings.Contains(d, "kit") {
			t.Errorf("toy depends on %s", d)
		}
	}
}
