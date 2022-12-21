package integration

import (
	"net/netip"
	"net/url"

	"tailscale.com/ipn/ipnstate"
)

// nolint
type TailscaleClient interface {
	Hostname() string
	Shutdown() error
	Version() string
	Execute(command []string) (string, string, error)
	Up(loginServer, authKey string) error
	UpWithLoginURL(loginServer string) (*url.URL, error)
	Logout() error
	IPs() ([]netip.Addr, error)
	FQDN() (string, error)
	Status() (*ipnstate.Status, error)
	WaitForReady() error
	WaitForLogout() error
	WaitForPeers(expected int) error
	Ping(hostnameOrIP string) error
	ID() string
}
