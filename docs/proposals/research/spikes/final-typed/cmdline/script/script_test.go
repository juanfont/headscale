package script

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"spike/cmdline"
)

// TestDirectiveBits: the library's Directive is cobra's ShellCompDirective,
// bit for bit, so cobra's scripts read what Serve writes.
func TestDirectiveBits(t *testing.T) {
	for _, p := range [][2]int{
		{int(cmdline.Failed), int(cobra.ShellCompDirectiveError)},
		{int(cmdline.NoSpace), int(cobra.ShellCompDirectiveNoSpace)},
		{int(cmdline.NoFiles), int(cobra.ShellCompDirectiveNoFileComp)},
		{int(cmdline.FilterExt), int(cobra.ShellCompDirectiveFilterFileExt)},
		{int(cmdline.FilterDirs), int(cobra.ShellCompDirectiveFilterDirs)},
		{int(cmdline.KeepOrder), int(cobra.ShellCompDirectiveKeepOrder)},
	} {
		if p[0] != p[1] {
			t.Errorf("directive %d, cobra %d", p[0], p[1])
		}
	}
}

// TestWrite: the four shells name the program and call its __complete entry
// point; any other shell is an error.
func TestWrite(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		var b bytes.Buffer
		if err := Write(&b, sh, "prog"); err != nil || !strings.Contains(b.String(), "prog __complete") && !strings.Contains(b.String(), "__complete") {
			t.Errorf("%s: %v", sh, err)
		}
	}
	if err := Write(&bytes.Buffer{}, "tcsh", "prog"); err == nil {
		t.Error("tcsh: no error")
	}
}
