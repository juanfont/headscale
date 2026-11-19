package script

import (
	"bytes"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmdline"
	"github.com/spf13/cobra"
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

// TestWrite: the four shells register the script for the program and call
// its __complete entry point; any other shell is an error. The scripts call
// the program by the word the user typed, so the name shows only where the
// script registers itself.
func TestWrite(t *testing.T) {
	for sh, register := range map[string]string{
		"bash":       "-F __start_prog prog\n",
		"zsh":        "compdef _prog prog\n",
		"fish":       "complete -c prog ",
		"powershell": "-CommandName 'prog' ",
	} {
		var b bytes.Buffer

		err := Write(&b, sh, "prog")
		if err != nil || !strings.Contains(b.String(), " __complete ") ||
			!strings.Contains(b.String(), register) {
			t.Errorf("%s: %v", sh, err)
		}
	}

	err := Write(&bytes.Buffer{}, "tcsh", "prog")
	if err == nil {
		t.Error("tcsh: no error")
	}
}
