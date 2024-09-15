package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/samber/lo"
)

var errParseAuthPage = errors.New("failed to parse auth page")

type AuthWebFlowScenario struct {
	*Scenario
}

func TestAuthWebFlowAuthenticationPingAll(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	baseScenario, err := NewScenario(dockertestMaxWait())
	if err != nil {
		t.Fatalf("failed to create scenario: %s", err)
	}

	scenario := AuthWebFlowScenario{
		Scenario: baseScenario,
	}
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": len(MustTestVersions),
		"user2": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, hsic.WithTestName("webauthping"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
}

func TestAuthWebFlowLogoutAndRelogin(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	baseScenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)

	scenario := AuthWebFlowScenario{
		Scenario: baseScenario,
	}
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": len(MustTestVersions),
		"user2": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, hsic.WithTestName("weblogout"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	clientIPs := make(map[TailscaleClient][]netip.Addr)
	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Fatalf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}
		clientIPs[client] = ips
	}

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	err = scenario.WaitForTailscaleLogout()
	assertNoErrLogout(t, err)

	t.Logf("all clients logged out")

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	for userName := range spec {
		err = scenario.runTailscaleUp(userName, headscale.GetEndpoint())
		if err != nil {
			t.Fatalf("failed to run tailscale up: %s", err)
		}
	}

	t.Logf("all clients logged in again")

	allClients, err = scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err = scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	allAddrs = lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success = pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Fatalf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}

		// lets check if the IPs are the same
		if len(ips) != len(clientIPs[client]) {
			t.Fatalf("IPs changed for client %s", client.Hostname())
		}

		for _, ip := range ips {
			found := false
			for _, oldIP := range clientIPs[client] {
				if ip == oldIP {
					found = true

					break
				}
			}

			if !found {
				t.Fatalf(
					"IPs changed for client %s. Used to be %v now %v",
					client.Hostname(),
					clientIPs[client],
					ips,
				)
			}
		}
	}

	t.Logf("all clients IPs are the same")
}

func (s *AuthWebFlowScenario) CreateHeadscaleEnv(
	users map[string]int,
	opts ...hsic.Option,
) error {
	headscale, err := s.Headscale(opts...)
	if err != nil {
		return err
	}

	err = headscale.WaitForRunning()
	if err != nil {
		return err
	}

	for userName, clientCount := range users {
		log.Printf("creating user %s with %d clients", userName, clientCount)
		err = s.CreateUser(userName)
		if err != nil {
			return err
		}

		err = s.CreateTailscaleNodesInUser(userName, "all", clientCount)
		if err != nil {
			return err
		}

		err = s.runTailscaleUp(userName, headscale.GetEndpoint())
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *AuthWebFlowScenario) runTailscaleUp(
	userStr, loginServer string,
) error {
	log.Printf("running tailscale up for user %s", userStr)
	if user, ok := s.users[userStr]; ok {
		for _, client := range user.Clients {
			c := client
			user.joinWaitGroup.Go(func() error {
				loginURL, err := c.LoginWithURL(loginServer)
				if err != nil {
					log.Printf("failed to run tailscale up (%s): %s", c.Hostname(), err)

					return err
				}

				err = s.runHeadscaleRegister(userStr, loginURL)
				if err != nil {
					log.Printf("failed to register client (%s): %s", c.Hostname(), err)

					return err
				}

				return nil
			})

			err := client.WaitForRunning()
			if err != nil {
				log.Printf("error waiting for client %s to be ready: %s", client.Hostname(), err)
			}
		}

		if err := user.joinWaitGroup.Wait(); err != nil {
			return err
		}

		for _, client := range user.Clients {
			err := client.WaitForRunning()
			if err != nil {
				return fmt.Errorf("%s failed to up tailscale node: %w", client.Hostname(), err)
			}
		}

		return nil
	}

	return fmt.Errorf("failed to up tailscale node: %w", errNoUserAvailable)
}

func (s *AuthWebFlowScenario) runHeadscaleRegister(userStr string, loginURL *url.URL) error {
	headscale, err := s.Headscale()
	if err != nil {
		return err
	}

	log.Printf("loginURL: %s", loginURL)
	loginURL.Host = fmt.Sprintf("%s:8080", headscale.GetIP())
	loginURL.Scheme = "http"

	httpClient := &http.Client{}
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, loginURL.String(), nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// see api.go HTML template
	codeSep := strings.Split(string(body), "</code>")
	if len(codeSep) != 2 {
		return errParseAuthPage
	}

	keySep := strings.Split(codeSep[0], "key ")
	if len(keySep) != 2 {
		return errParseAuthPage
	}
	key := keySep[1]
	log.Printf("registering node %s", key)

	if headscale, err := s.Headscale(); err == nil {
		_, err = headscale.Execute(
			[]string{"headscale", "nodes", "register", "--user", userStr, "--key", key},
		)
		if err != nil {
			log.Printf("failed to register node: %s", err)

			return err
		}

		return nil
	}

	return fmt.Errorf("failed to find headscale: %w", errNoHeadscaleAvailable)
}
