package newcli

import (
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
)

type completionIn struct {
	Shell command.OneOf[command.Shells] `arg:"shell" help:"<shell> is bash, zsh, fish or powershell."`
}

var completionCmd = command.New(command.Spec[completionIn, command.NoOutput]{
	Name:  "completion",
	Short: "Print the completion script of a shell",
	Long: `Print the completion script of a shell to stdout.

The script calls headscale itself to answer Tab, so it completes the
commands, the flags and their values of the binary that runs. Tab reads no
config and never calls the server. bash, zsh and fish are tested in real
shells; PowerShell gets a script too.

To load completions in the running shell:

  bash:        source <(headscale completion bash)
  zsh:         source <(headscale completion zsh)
  fish:        headscale completion fish | source
  PowerShell:  headscale completion powershell | Out-String | Invoke-Expression`,
	Example: []string{
		"headscale completion bash",
		"headscale completion zsh",
		"headscale completion fish",
		"headscale completion powershell",
	},
	Local: true,
	Run:   func(command.Ctx, completionIn) (command.NoOutput, error) { return command.NoOutput{}, nil },
	Done: func(in completionIn, _ command.NoOutput, _ time.Time) string {
		var b strings.Builder
		// The shell is one of Shells, and a Builder takes every write.
		_ = command.Script(&b, in.Shell, "headscale")

		return b.String()
	},
})
