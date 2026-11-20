package own

import (
	"bytes"
	"strings"
	"testing"
)

func TestComplete(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"", "version\tPrint the version|nodes\tManage nodes|auth\tAuth keys|policy\tPolicy|check\tCheck files|completion\tShell completion script|debug\tDebug|:4"},
		{"no", "nodes\tManage nodes|:4"},
		{"-c x no", "nodes\tManage nodes|:4"},
		{"nodes ", "list\tList the nodes|delete\tDelete a node|set\tChange a node|routes\tManage routes|:4"},
		{"nodes routes ", "set\tReplace the routes|:4"},
		{"nodes rm --f", "--force\tDo not ask|:4"},
		{"nodes list --sort ", "id|name|owner|ip|last-seen|online|:6"},
		{"nodes list --sort -l", "-last-seen|:6"},
		{"nodes list --columns id,na", "id,name|:6"},
		{"nodes list --columns id,+o", "id,+owner|id,+online|:6"},
		{"nodes list --columns=id,na", "id,name|:6"},
		{"nodes list -o ", "json|:4"},
		{"nodes list -o=j", "json|:4"},
		{"-o ", "json|:4"},
		{"version --output ", "json|:4"},
		{"policy set ", ":0"},
		{"completion f", "fish|:4"},
		{"check config -", "--config\tConfig file|--help\tShow help|:4"},
		{"bogus ", ":4"},
	} {
		var b bytes.Buffer
		Serve(&b, Tree(), strings.Split(tc.line, " "), true)
		got := strings.ReplaceAll(strings.TrimSuffix(b.String(), "\n"), "\n", "|")
		if got != tc.want {
			t.Errorf("%q\n got %q\nwant %q", tc.line, got, tc.want)
		}
	}
}
