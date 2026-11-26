package newcli

import (
	"errors"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/types/key"
)

// The pages are made by the binary that has this tree, so a stale page
// shows as a change after `make generate`.
//go:generate sh -c "go run -tags newcli .. generate cli-reference > ../../../docs/ref/cli.md"
//go:generate sh -c "go run -tags newcli .. generate man > ../../../docs/ref/headscale.1"

var generateGroup = command.Group{
	Name:     "generate",
	Short:    "Print a key, a config file or the pages made from the code",
	OldNames: []string{"gen"},
	Commands: []command.Node{
		generatePrivateKey,
		generateConfig,
		generateNixOSOptions,
		generateCLIReference,
		generateMan,
	},
}

type (
	generateConfigIn struct {
		NoDocs  bool `flag:"no-docs" help:"Leave out the documentation comments"`
		Running bool `flag:"running" help:"Print the running server's configuration, secrets removed, instead of the defaults"`
		Minimal bool `flag:"minimal" help:"Print only the keys every server must set"`
	}
	generateNixOSOptionsIn struct {
		Release bool `flag:"release" help:"Stamp the version and commit of this binary, which must be a clean build of a known commit"`
	}
)

// errMinimalRunning is --minimal with --running, which prints every key of
// the server.
//
//nolint:staticcheck // a sentence of the CLI
var errMinimalRunning = errors.New(
	"--minimal and --running cannot be given together: the running configuration has every key.",
)

var generatePrivateKey = command.New(command.Spec[command.NoInput, command.Text]{
	Name:  "private-key",
	Short: "Print a new private key",
	Long: `Print a new private key for the headscale server, such as for
noise.private_key_path or derp.server.private_key_path, to stdout.

The key is printed alone. Headscale creates the key files that are missing
at startup; this is for a key made beforehand.`,
	Example: []string{"headscale generate private-key"},
	Local:   true,
	Run: func(command.Ctx, command.NoInput) (command.Text, error) {
		k, err := key.NewMachine().MarshalText()

		return command.Text(string(k) + "\n"), err
	},
})

var generateConfig = command.New(command.Spec[generateConfigIn, command.Text]{
	Name:  "config",
	Short: "Print a configuration file with every key",
	Long: `Print a YAML configuration with every key, its default and its
documentation as comments, as for "> /etc/headscale/config.yaml". Set the
keys marked "Required" before starting headscale. With --minimal, print only
those keys.

With --running, print instead the configuration of the running server,
without the client-only cli section: literal secrets, DNS provider settings
other than its name, and the credentials in URLs are removed, "file:"
references kept as written. --running asks the server, so it takes --config
and needs a server; the rest needs none.`,
	Example: []string{
		"headscale generate config",
		"headscale generate config --minimal",
		"headscale generate config --running",
	},
	OldNames:    []string{"dumpConfig --running"},
	Local:       true,
	NeedsServer: func(in generateConfigIn) bool { return in.Running },
	Valid: func(in generateConfigIn) error {
		if in.Minimal && in.Running {
			return errMinimalRunning
		}

		return nil
	},
	Run: func(c command.Ctx, in generateConfigIn) (command.Text, error) {
		if in.Running {
			// A text is printed as the server wrote it.
			resp, err := c.API.GetConfigWithResponse(
				c,
				&clientv0.GetConfigParams{Docs: new(!in.NoDocs)},
			)
			if err == nil {
				err = resp.Err()
			}

			if err != nil {
				return "", err
			}

			return command.Text(resp.Body), nil
		}

		d := config.Default()
		out, err := config.GenerateExample(
			&d,
			config.ExampleOptions{Docs: !in.NoDocs, Minimal: in.Minimal},
		)

		return command.Text(out), err
	},
})

var generateNixOSOptions = command.New(
	command.Spec[generateNixOSOptionsIn, command.Text]{
		Name:  "nixos-options",
		Short: "Print the NixOS options for services.headscale.settings",
		Long: `Print the NixOS options for services.headscale.settings: one option per
configuration key, with its type, default, documentation and an example. The
output is a function of lib only, not a module:

    options = import ./options.generated.nix { inherit lib; };

With --release, its header names this binary's version and commit instead
of the development tree.`,
		Example: []string{"headscale generate nixos-options"},
		Local:   true,
		Run: func(c command.Ctx, in generateNixOSOptionsIn) (command.Text, error) {
			var stamp *types.VersionInfo

			if in.Release {
				var err error

				stamp, err = config.ReleaseStamp(c.API.Build())
				if err != nil {
					return "", err
				}
			}

			out, err := config.GenerateNixOptions(stamp)

			return command.Text(out), err
		},
	},
)

var generateCLIReference = command.New(command.Spec[command.NoInput, command.Text]{
	Name:  "cli-reference",
	Short: "Print the reference page of the command line",
	Long: `Print the reference page of the command line, in Markdown: the command
tree, the flags that more than one command takes, the short flags, the
aliases, and the help of every command, with the columns of each list.

It is made from the command specs, as the help is, and committed as
docs/ref/cli.md. A check fails when the committed page is stale.`,
	Example: []string{"headscale generate cli-reference"},
	Local:   true,
	Run: func(c command.Ctx, _ command.NoInput) (command.Text, error) {
		return command.Text(c.Reference()), nil
	},
})

var generateMan = command.New(command.Spec[command.NoInput, command.Text]{
	Name:  "man",
	Short: "Print the man page",
	Long: `Print the man page headscale(1), in roff: one page with the command tree
and every command, as the reference page has them.

It is made from the command specs, as the help is, and committed as
docs/ref/headscale.1, which a package installs. A check fails when the
committed page is stale.`,
	Example: []string{"headscale generate man"},
	Local:   true,
	Run: func(c command.Ctx, _ command.NoInput) (command.Text, error) {
		return command.Text(c.Man()), nil
	},
})
