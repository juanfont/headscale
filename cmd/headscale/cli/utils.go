package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"

	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	HeadscaleDateTimeFormat = "2006-01-02 15:04:05"
	SocketWritePermissions  = 0o666

	outputFormatJSON     = "json"
	outputFormatJSONLine = "json-line"
	outputFormatYAML     = "yaml"
)

var (
	errAPIKeyNotSet     = errors.New("HEADSCALE_CLI_API_KEY environment variable needs to be set")
	errMissingParameter = errors.New("missing parameters")
)

// mustMarkRequired marks the named flags as required on cmd, panicking
// if any name does not match a registered flag.  This is only called
// from init() where a failure indicates a programming error.
func mustMarkRequired(cmd *cobra.Command, names ...string) {
	for _, n := range names {
		err := cmd.MarkFlagRequired(n)
		if err != nil {
			panic(fmt.Sprintf("marking flag %q required on %q: %v", n, cmd.Name(), err))
		}
	}
}

func newHeadscaleServerWithConfig() (*hscontrol.Headscale, error) {
	cfg, err := types.LoadServerConfig()
	if err != nil {
		return nil, fmt.Errorf(
			"loading configuration: %w",
			err,
		)
	}

	app, err := hscontrol.NewHeadscale(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating new headscale: %w", err)
	}

	return app, nil
}

// addressableForJSON makes value-typed generated API structs (and slice
// elements) addressable so their pointer-receiver MarshalJSON is used. That
// method omits unset optional fields; stdlib reflection over a value instead
// calls Opt*.MarshalJSON directly, which returns empty for an unset field and
// fails with "unexpected end of JSON input".
func addressableForJSON(v any) any {
	rv := reflect.ValueOf(v)

	switch rv.Kind() { //nolint:exhaustive // default handles all other kinds
	case reflect.Slice, reflect.Array:
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = addressableForJSON(rv.Index(i).Interface())
		}

		return out
	case reflect.Struct:
		p := reflect.New(rv.Type())
		p.Elem().Set(rv)

		return p.Interface()
	default:
		return v
	}
}

// formatOutput serialises result into the requested format. For the
// default (empty) format the human-readable override string is returned.
func formatOutput(result any, override string, outputFormat string) (string, error) {
	result = addressableForJSON(result)

	switch outputFormat {
	case outputFormatJSON:
		b, err := json.MarshalIndent(result, "", "\t")
		if err != nil {
			return "", fmt.Errorf("marshalling JSON output: %w", err)
		}

		return string(b), nil
	case outputFormatJSONLine:
		b, err := json.Marshal(result)
		if err != nil {
			return "", fmt.Errorf("marshalling JSON-line output: %w", err)
		}

		return string(b), nil
	case outputFormatYAML:
		// Route through JSON so types with a custom MarshalJSON (the generated
		// API types) serialise by their JSON shape, then convert to YAML.
		j, err := json.Marshal(result)
		if err != nil {
			return "", fmt.Errorf("marshalling output: %w", err)
		}

		var generic any

		err = yaml.Unmarshal(j, &generic)
		if err != nil {
			return "", fmt.Errorf("converting output to YAML: %w", err)
		}

		b, err := yaml.Marshal(generic)
		if err != nil {
			return "", fmt.Errorf("marshalling YAML output: %w", err)
		}

		return string(b), nil
	default:
		return override, nil
	}
}

// printOutput formats result and writes it to stdout. It reads the --output
// flag from cmd to decide the serialisation format.
func printOutput(cmd *cobra.Command, result any, override string) error {
	format, _ := cmd.Flags().GetString("output")

	out, err := formatOutput(result, override, format)
	if err != nil {
		return err
	}

	fmt.Println(out)

	return nil
}

// confirmAction returns true when the user confirms a prompt, or when
// --force is set.  Callers decide what to do when it returns false.
func confirmAction(cmd *cobra.Command, prompt string) bool {
	force, _ := cmd.Flags().GetBool("force")
	if force {
		return true
	}

	return util.YesNo(prompt)
}

// renderTable prints a human-readable pterm table with the given header row
// and data rows, using the shared header styling.
func renderTable(header []string, rows [][]string) error {
	tableData := make(pterm.TableData, 0, 1+len(rows))
	tableData = append(tableData, header)
	tableData = append(tableData, rows...)

	return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
}

// printListOutput checks the --output flag: when a machine-readable format is
// requested it serialises data as JSON/YAML; otherwise it calls the render
// callback to produce the human-readable pterm table.
func printListOutput(
	cmd *cobra.Command,
	data any,
	renderTable func() error,
) error {
	format, _ := cmd.Flags().GetString("output")
	if format != "" {
		return printOutput(cmd, data, "")
	}

	return renderTable()
}

// printError writes err to stderr, formatting it as JSON/YAML when the
// --output flag requests machine-readable output.  Used exclusively by
// [Execute] so that every error surfaces in the format the caller asked for.
func printError(err error, outputFormat string) {
	type errOutput struct {
		Error string `json:"error"`
	}

	if outputFormat == "" {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)

		return
	}

	// formatOutput cannot fail here: errOutput is a single string field.
	out, _ := formatOutput(errOutput{Error: err.Error()}, "", outputFormat)
	fmt.Fprintf(os.Stderr, "%s\n", out)
}

func hasMachineOutputFlag() bool {
	return slices.ContainsFunc(os.Args, func(arg string) bool {
		return arg == outputFormatJSON || arg == outputFormatJSONLine || arg == outputFormatYAML
	})
}
