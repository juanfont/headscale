package integration

import (
	"net/netip"

	"tailscale.com/ipn/ipnstate"
)

type TailscaleClient interface {
	Hostname() string
	Shutdown() error
	Version() string
	Up(loginServer, authKey string) error
	IPs() ([]netip.Addr, error)
	Status() (*ipnstate.Status, error)
	WaitForPeers(expected int) error
	Ping(ip netip.Addr) error
}
