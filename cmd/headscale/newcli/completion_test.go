package newcli

import (
	"bytes"
	"testing"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/stretchr/testify/require"
)

// script is the completion script of shell.
func script(shell string) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, _ *fixture, _ result) string {
		tb.Helper()

		var b bytes.Buffer
		require.NoError(tb, command.Script(&b, command.OneOf[command.Shells](shell), "headscale"))

		return b.String()
	}
}

var completionCases = []cliCase{
	{name: "bash", args: "completion bash", want: script("bash")},
	{name: "zsh", args: "completion zsh", want: script("zsh")},
	{name: "fish", args: "completion fish", want: script("fish")},
	{name: "powershell", args: "completion powershell", want: script("powershell")},
	{
		name:   "an unknown shell",
		args:   "completion tcsh",
		stderr: "Error: \"tcsh\" is not a valid <shell>: it is one of bash, zsh, fish, powershell.\n",
		code:   1,
	},
	{name: "no shell", args: "completion", stderr: "Error: `completion` needs 1 argument, got 0.\n\n  headscale completion <shell>\n", code: 1},
	{name: "no --output", args: "completion bash -o json", stderr: "Error: --output does not apply to `completion`.\nRun `headscale completion --help`.\n", code: 1},
	{name: "no -o before it either", args: "-o json completion bash", stderr: "Error: --output does not apply to `completion`.\nRun `headscale completion --help`.\n", code: 1},
	{name: "Tab offers the shells", args: "__complete completion ''", stdout: "bash\nzsh\nfish\npowershell\n:4\n"},
	{
		name:   "Tab offers the commands",
		args:   "__complete ''",
		stdout: "version\tPrint the version\ncompletion\tPrint the completion script of a shell\napi\tAuthentication towards the headscale API\ndebug\tA health check and test tools\n:4\n",
	},
}

func TestCompletion(t *testing.T) {
	t.Parallel()

	runCases(t, nil, completionCases)
}
