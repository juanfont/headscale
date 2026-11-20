package servertest_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/dns/dnstest"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/netmap"
)

// hasIngressGrantFrom reports whether nm's packet filter gives src the
// ingress capability, as a funnel node needs to accept a relay's requests.
func hasIngressGrantFrom(nm *netmap.NetworkMap, src netip.Addr) bool {
	if nm == nil {
		return false
	}

	for _, r := range nm.PacketFilterRules.All() {
		if !slices.ContainsFunc(r.SrcIPs, func(s string) bool {
			p, err := netip.ParsePrefix(s)
			if err == nil {
				return p.Contains(src)
			}

			a, err := netip.ParseAddr(s)

			return err == nil && a == src
		}) {
			continue
		}

		for _, cg := range r.CapGrant {
			if _, ok := cg.CapMap[peercap.Ingress]; ok {
				return true
			}
		}
	}

	return false
}

func hasPeerNamed(nm *netmap.NetworkMap, name string) bool {
	if nm == nil {
		return false
	}

	for _, p := range nm.Peers {
		if p.Hostinfo().Hostname() == name {
			return true
		}
	}

	return false
}

// TestFunnel checks what the control plane gives a funnel node and its
// relay: the node gets the funnel and funnel-ports caps next to https,
// and the ingress capability from the relay, which becomes its peer even
// though the ACL links neither.
func TestFunnel(t *testing.T) {
	t.Parallel()

	const domain = "ts.example.com"

	srv := servertest.NewServer(t,
		servertest.WithMagicDNS(domain),
		servertest.WithCertificates(&dnstest.Provider{}),
		servertest.WithFunnel("tag:relay"),
	)
	user := srv.CreateUser(t, "funnel-user")

	reloadPolicy(t, srv, `{
		"tagOwners": {"tag:relay": ["funnel-user@"], "tag:other": ["funnel-user@"]},
		"acls": [{"action": "accept", "src": ["tag:other"], "dst": ["tag:other:*"]}],
		"nodeAttrs": [{"target": ["funnel-user@"], "attr": ["funnel"]}]
	}`)

	laptop := servertest.NewClient(t, srv, "laptop", servertest.WithUser(user))
	relay := servertest.NewClient(t, srv, "relay", servertest.WithUser(user), servertest.WithTags("tag:relay"))

	relay.WaitForCondition(t, "relay sees laptop", 10*time.Second,
		func(nm *netmap.NetworkMap) bool { return hasPeerNamed(nm, "laptop") })
	relayIP := relay.Netmap().SelfNode.Addresses().At(0).Addr()

	portsCap := nodecap.Cap("https://tailscale.com/cap/funnel-ports?ports=443,8443,10000")

	laptop.WaitForCondition(t, "funnel caps and ingress from relay", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasCap(nm, nodecap.HTTPS) &&
				hasCap(nm, nodecap.Funnel) &&
				hasCap(nm, portsCap) &&
				hasPeerNamed(nm, "relay") &&
				hasIngressGrantFrom(nm, relayIP)
		})

	// The relay is tagged, so the user-targeted funnel attr is not its.
	relay.WaitForCondition(t, "relay has no funnel attr", 10*time.Second,
		func(nm *netmap.NetworkMap) bool { return nm != nil && !hasCap(nm, nodecap.Funnel) })
}

// TestFunnelDisabled checks that without funnel in the server config the
// funnel attr stays off the node and no ingress capability is granted.
func TestFunnelDisabled(t *testing.T) {
	t.Parallel()

	const domain = "ts.example.com"

	srv := servertest.NewServer(t,
		servertest.WithMagicDNS(domain),
		servertest.WithCertificates(&dnstest.Provider{}),
	)
	user := srv.CreateUser(t, "funnel-user")

	reloadPolicy(t, srv, `{
		"tagOwners": {"tag:relay": ["funnel-user@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		"nodeAttrs": [{"target": ["funnel-user@"], "attr": ["funnel"]}]
	}`)

	laptop := servertest.NewClient(t, srv, "laptop", servertest.WithUser(user))
	relay := servertest.NewClient(t, srv, "relay", servertest.WithUser(user), servertest.WithTags("tag:relay"))

	relay.WaitForCondition(t, "relay sees laptop", 10*time.Second,
		func(nm *netmap.NetworkMap) bool { return hasPeerNamed(nm, "laptop") })
	relayIP := relay.Netmap().SelfNode.Addresses().At(0).Addr()

	laptop.WaitForCondition(t, "https without funnel", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasCap(nm, nodecap.HTTPS) && hasPeerNamed(nm, "relay")
		})

	nm := laptop.Netmap()

	if hasCap(nm, nodecap.Funnel) {
		t.Error("funnel attr delivered while funnel is disabled")
	}

	if hasIngressGrantFrom(nm, relayIP) {
		t.Error("ingress granted while funnel is disabled")
	}
}
