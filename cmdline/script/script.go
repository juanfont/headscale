// Package script writes the completion scripts that call a program's
// hidden __complete entry point (cmdline.Tree.Serve). The scripts are cobra's
// (D23): this package imports cobra for its generators and nothing else.
package script

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

var errShell = errors.New("no completion script for shell")

// Write writes the script for shell ("bash", "zsh", "fish" or
// "powershell") for the program named program, with descriptions.
func Write(w io.Writer, shell, program string) error {
	if shell == "fish" &&
		strings.ContainsFunc(
			program,
			func(r rune) bool { return !strings.ContainsRune(fishName, r) },
		) {
		return fmt.Errorf("program %q: %w", program, errFishName)
	}

	c := &cobra.Command{Use: program}

	switch shell {
	case "bash":
		return c.GenBashCompletionV2(w, true)
	case "zsh":
		return c.GenZshCompletion(w)
	case "fish":
		return c.GenFishCompletion(w, true)
	case "powershell":
		return c.GenPowerShellCompletionWithDesc(w)
	}

	return fmt.Errorf("%w %q", errShell, shell)
}

// fishName is what cobra's fish script may hold in a variable name, which
// it makes of the program's name with "-" turned into "_".
const fishName = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

var errFishName = errors.New(
	"fish names its variables after the program: use letters, digits, - and _",
)
