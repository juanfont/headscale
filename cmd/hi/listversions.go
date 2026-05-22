package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/creachadair/command"
	"github.com/juanfont/headscale/hscontrol/capver"
)

var (
	errUnknownSet    = errors.New("unknown --set value (want must|all)")
	errUnknownFormat = errors.New("unknown --format value (want space|newline|json)")
)

// ListVersionsConfig holds flags for the list-versions subcommand.
type ListVersionsConfig struct {
	Set     string `flag:"set,default=must,Version set: must|all"`
	Exclude string `flag:"exclude,Comma-separated versions to exclude (e.g. head,unstable)"`
	Format  string `flag:"format,default=space,Output format: space|newline|json"`
}

var listVersionsConfig ListVersionsConfig

// listVersions prints the Tailscale versions used by integration tests
// in a format CI can shell out to. Mirrors integration/scenario.go
// AllVersions and MustTestVersions: "head" and "unstable" are bare
// tags, releases get a "v" prefix so each entry can be appended to
// "ghcr.io/tailscale/tailscale:" directly.
func listVersions(env *command.Env) error {
	release := capver.TailscaleLatestMajorMinor(capver.SupportedMajorMinorVersions, true)
	all := append([]string{"head", "unstable"}, release...)
	must := append(append([]string{}, all[0:4]...), all[len(all)-2:]...)

	var versions []string

	switch listVersionsConfig.Set {
	case "must":
		versions = must
	case "all":
		versions = all
	default:
		return fmt.Errorf("%w: %q", errUnknownSet, listVersionsConfig.Set)
	}

	excluded := make(map[string]bool)

	if listVersionsConfig.Exclude != "" {
		for v := range strings.SplitSeq(listVersionsConfig.Exclude, ",") {
			excluded[strings.TrimSpace(v)] = true
		}
	}

	out := make([]string, 0, len(versions))

	for _, v := range versions {
		if excluded[v] {
			continue
		}

		if v != "head" && v != "unstable" {
			v = "v" + v
		}

		out = append(out, v)
	}

	switch listVersionsConfig.Format {
	case "space":
		fmt.Println(strings.Join(out, " "))
	case "newline":
		for _, v := range out {
			fmt.Println(v)
		}
	case "json":
		b, err := json.Marshal(out)
		if err != nil {
			return err
		}

		fmt.Println(string(b))
	default:
		return fmt.Errorf("%w: %q", errUnknownFormat, listVersionsConfig.Format)
	}

	return nil
}
