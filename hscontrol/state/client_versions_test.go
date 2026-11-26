package state

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestUpdateAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":"1.90.0","TarballsVersion":"1.90.2","MSIsVersion":"1.90.1","MacZipsVersion":"1.90.0","SPKsVersion":"1.88.0","GAFsVersion":"1.89.0"}`))
	}))
	t.Cleanup(srv.Close)

	v, err := FetchClientVersions(t.Context(), srv.Client(), srv.URL)
	require.NoError(t, err)
	require.Equal(t, ClientVersions{Tarballs: "1.90.2", MSIs: "1.90.1", MacZips: "1.90.0", SPKs: "1.88.0", GAFs: "1.89.0"}, v)

	s := &State{}
	node := func(hi *tailcfg.Hostinfo) types.NodeView { return (&types.Node{Hostinfo: hi}).View() }
	linux := node(&tailcfg.Hostinfo{OS: "linux", IPNVersion: "1.90.0-t0123abc-g4567def"})

	before := s.UpdateAvailable()
	require.False(t, before(linux), "no list read yet")

	s.SetClientVersions(v)
	require.False(t, before(linux), "a page is judged against the list read when it began")
	require.True(t, s.UpdateAvailable()(linux))

	for _, tt := range []struct {
		name string
		hi   *tailcfg.Hostinfo
		want bool
	}{
		{"linux behind", &tailcfg.Hostinfo{OS: "linux", IPNVersion: "1.90.0-t0123abc"}, true},
		{"linux current", &tailcfg.Hostinfo{OS: "linux", IPNVersion: "1.90.2"}, false},
		{"linux ahead", &tailcfg.Hostinfo{OS: "linux", IPNVersion: "1.91.0"}, false},
		{"synology reads its own package", &tailcfg.Hostinfo{OS: "linux", Distro: "synology", IPNVersion: "1.88.0"}, false},
		{"gokrazy reads its own image", &tailcfg.Hostinfo{OS: "linux", Distro: "gokrazy", IPNVersion: "1.89.0"}, false},
		{"gokrazy behind", &tailcfg.Hostinfo{OS: "linux", Distro: "gokrazy", IPNVersion: "1.88.0"}, true},
		{"windows", &tailcfg.Hostinfo{OS: "windows", IPNVersion: "1.88.0"}, true},
		{"macOS", &tailcfg.Hostinfo{OS: "macOS", IPNVersion: "1.90.0"}, false},
		{"iOS has no version in the list", &tailcfg.Hostinfo{OS: "iOS", IPNVersion: "1.2.0"}, false},
		{"no version reported", &tailcfg.Hostinfo{OS: "linux"}, false},
		{"no hostinfo", nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, s.UpdateAvailable()(node(tt.hi)))
		})
	}

	bad := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(bad.Close)

	_, err = FetchClientVersions(t.Context(), bad.Client(), bad.URL)
	require.Error(t, err)
}
