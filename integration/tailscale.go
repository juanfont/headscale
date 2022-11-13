package integration

import (
	"net/netip"

	"tailscale.com/ipn/ipnstate"
)

type TailscaleClient interface {
	Hostname() string
	Shutdown() error
	Version() string
	Execute(command []string) (string, error)
	Up(loginServer, authKey string) error
	IPs() ([]netip.Addr, error)
	FQDN() (string, error)
	Status() (*ipnstate.Status, error)
	WaitForReady() error
	WaitForPeers(expected int) error
	Ping(hostnameOrIP string) error
}
