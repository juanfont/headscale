package integration

import (
	"net/netip"
	"net/url"

	"tailscale.com/ipn/ipnstate"
)

type TailscaleClient interface {
	Hostname() string
	Shutdown() error
	Version() string
	Execute(command []string) (string, error)
	Up(loginServer, authKey string) error
	UpWithLoginURL(loginServer string) (*url.URL, error)
	IPs() ([]netip.Addr, error)
	FQDN() (string, error)
	Status() (*ipnstate.Status, error)
	WaitForPeers(expected int) error
	Ping(hostnameOrIP string) error
}
