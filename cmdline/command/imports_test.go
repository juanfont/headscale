package command

import (
	gobuild "go/build"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestImportsNoProgram: the library, its table engine and its durations
// are for any program: they import no package of Headscale but the
// parser's own. What is a program's comes in through its Program.
func TestImportsNoProgram(t *testing.T) {
	t.Parallel()

	for _, dir := range []string{".", "../table", "../duration"} {
		pkg, err := gobuild.ImportDir(dir, 0)
		require.NoError(t, err)

		for _, imp := range pkg.Imports {
			require.True(
				t,
				!strings.HasPrefix(imp, "github.com/juanfont/headscale/") ||
					strings.HasPrefix(imp, "github.com/juanfont/headscale/cmdline"),
				"%s imports %s",
				dir,
				imp,
			)
		}
	}
}
