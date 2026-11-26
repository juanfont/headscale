package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/util/cmpver"
)

// ClientVersionsURL lists the newest stable Tailscale client of each kind
// of package.
const ClientVersionsURL = "https://pkgs.tailscale.com/stable/?mode=json"

var errHTTPStatus = errors.New("unexpected HTTP status")

// maxClientVersionsBody bounds the list; it is a few kilobytes.
const maxClientVersionsBody = 1 << 20

// ClientVersions is the newest stable client of each kind of package, as
// tailscale.com/clientupdate reads them for each platform.
type ClientVersions struct {
	Tarballs string `json:"TarballsVersion"`
	MSIs     string `json:"MSIsVersion"`
	MacZips  string `json:"MacZipsVersion"`
	SPKs     string `json:"SPKsVersion"`
	GAFs     string `json:"GAFsVersion"`
}

// FetchClientVersions reads the list at url.
func FetchClientVersions(ctx context.Context, client *http.Client, url string) (ClientVersions, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ClientVersions{}, fmt.Errorf("building request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return ClientVersions{}, fmt.Errorf("fetching client versions: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return ClientVersions{}, fmt.Errorf("fetching client versions: %w: %s", errHTTPStatus, res.Status)
	}

	var v ClientVersions

	err = json.NewDecoder(io.LimitReader(res.Body, maxClientVersionsBody)).Decode(&v)
	if err != nil {
		return ClientVersions{}, fmt.Errorf("decoding client versions: %w", err)
	}

	return v, nil
}

// SetClientVersions keeps v as the newest clients; see [State.UpdateAvailable].
func (s *State) SetClientVersions(v ClientVersions) {
	s.clientVersions.Store(&v)
}

// UpdateAvailable reports, against the list read now, whether a newer stable
// Tailscale client exists than the one a node runs, so that a page of nodes
// is judged against one list. It is false when that is not known: no list was
// read, the node reports no version, or the list has none for its platform,
// as for iOS and Android.
func (s *State) UpdateAvailable() func(types.NodeView) bool {
	latest := s.clientVersions.Load()

	return func(nv types.NodeView) bool { return updateAvailable(latest, nv) }
}

func updateAvailable(latest *ClientVersions, nv types.NodeView) bool {
	hi := nv.Hostinfo()
	if latest == nil || !hi.Valid() {
		return false
	}

	running, _, _ := strings.Cut(hi.IPNVersion(), "-")

	var newest string

	switch {
	case hi.OS() == "linux" && hi.Distro() == "synology":
		newest = latest.SPKs
	case hi.OS() == "linux" && hi.Distro() == "gokrazy":
		newest = latest.GAFs
	case hi.OS() == "linux":
		newest = latest.Tarballs
	case hi.OS() == "windows":
		newest = latest.MSIs
	case hi.OS() == "macOS":
		newest = latest.MacZips
	}

	return running != "" && newest != "" && cmpver.Compare(newest, running) > 0
}
