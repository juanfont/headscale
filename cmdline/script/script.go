// Package script writes the completion scripts that call a program's
// hidden __complete entry point (cmdline.Tree.Serve). The scripts are cobra's
// (D23): this package imports cobra for its generators and nothing else.
package script

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

var errShell = errors.New("no completion script for shell")

// Cobra's fish script splits a lone candidate without "--", so fish takes
// one that starts with "-", such as "--columns=id,name", as an option of
// string split and prints an error instead of completing.
var (
	fishSplit      = []byte(`string split --max 1 \t $__`)
	fishSplitFixed = []byte(`string split --max 1 -- \t $__`)
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
		var b bytes.Buffer

		err := c.GenFishCompletion(&b, true)
		if err != nil {
			return err
		}

		_, err = w.Write(bytes.Replace(b.Bytes(), fishSplit, fishSplitFixed, 1))

		return err
	case "powershell":
		return c.GenPowerShellCompletionWithDesc(w)
	}

	return fmt.Errorf("%w %q", errShell, shell)
}
