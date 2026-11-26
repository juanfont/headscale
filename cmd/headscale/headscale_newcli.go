//go:build newcli

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"runtime"

	"github.com/juanfont/headscale/cmd/headscale/newcli"
	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
)

func main() {
	env := command.OSEnv()
	env.Releases = releases("https://api.github.com/repos/juanfont/headscale/tags?per_page=100")

	os.Exit(command.Run(newcli.Tree(), os.Args[1:], env))
}

var errReleases = errors.New("listing the releases")

// releases lists the tags of headscale at url, the GitHub API. The request
// ends with its context, so an answer that does not come is not waited for
// past the run's timeout.
func releases(url string) func(context.Context) ([]string, error) {
	return func(ctx context.Context) ([]string, error) {
		if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
			return nil, nil
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, errors.Join(errReleases, errors.New(resp.Status)) //nolint:err113 // GitHub's status
		}

		var tags []struct{ Name string }

		err = json.NewDecoder(resp.Body).Decode(&tags)
		if err != nil {
			return nil, err
		}

		out := make([]string, 0, len(tags))
		for _, t := range tags {
			out = append(out, t.Name)
		}

		return out, nil
	}
}
