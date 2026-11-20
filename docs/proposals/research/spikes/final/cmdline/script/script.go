// Package script writes the completion scripts that call a program's
// hidden __complete entry point (cmdline.Serve). The scripts are cobra's
// (D23): this package imports cobra for its generators and nothing else.
package script

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// Write writes the script for shell ("bash", "zsh", "fish" or
// "powershell") for the program named program, with descriptions.
func Write(w io.Writer, shell, program string) error {
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
	return fmt.Errorf("no completion script for shell %q", shell)
}
