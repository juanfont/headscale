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
)

var errParseAuthPage = errors.New("failed to parse auth page")

type AuthWebFlowScenario struct {
	*Scenario
}

func TestAuthWebFlowAuthenticationPingAll(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	baseScenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario := AuthWebFlowScenario{
		Scenario: baseScenario,
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions),
		"user2": len(TailscaleVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, hsic.WithTestName("webauthping"))
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListTailscaleClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	success := 0
	for _, client := range allClients {
		for _, ip := range allIps {
			err := client.Ping(ip.String())
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", ip, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestAuthWebFlowLogoutAndRelogin(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	baseScenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario := AuthWebFlowScenario{
		Scenario: baseScenario,
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions),
		"user2": len(TailscaleVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, hsic.WithTestName("weblogout"))
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListTailscaleClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	success := 0
	for _, client := range allClients {
		for _, ip := range allIps {
			err := client.Ping(ip.String())
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", ip, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	clientIPs := make(map[TailscaleClient][]netip.Addr)
	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Errorf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}
		clientIPs[client] = ips
	}

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Errorf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	scenario.WaitForTailscaleLogout()

	t.Logf("all clients logged out")

	headscale, err := scenario.Headscale()
	if err != nil {
		t.Errorf("failed to get headscale server: %s", err)
	}

	for userName := range spec {
		err = scenario.runTailscaleUp(userName, headscale.GetEndpoint())
		if err != nil {
			t.Errorf("failed to run tailscale up: %s", err)
		}
	}

	t.Logf("all clients logged in again")

	allClients, err = scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err = scenario.ListTailscaleClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	success = 0
	for _, client := range allClients {
		for _, ip := range allIps {
			err := client.Ping(ip.String())
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", ip, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Errorf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}

		// lets check if the IPs are the same
		if len(ips) != len(clientIPs[client]) {
			t.Errorf("IPs changed for client %s", client.Hostname())
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
				t.Errorf("IPs changed for client %s. Used to be %v now %v", client.Hostname(), clientIPs[client], ips)
			}
		}
	}

	t.Logf("all clients IPs are the same")

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func (s *AuthWebFlowScenario) CreateHeadscaleEnv(
	users map[string]int,
	opts ...hsic.Option,
) error {
	headscale, err := s.Headscale(opts...)
	if err != nil {
		return err
	}

	err = headscale.WaitForReady()
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
			user.joinWaitGroup.Add(1)

			go func(c TailscaleClient) {
				defer user.joinWaitGroup.Done()

				// TODO(juanfont): error handle this
				loginURL, err := c.UpWithLoginURL(loginServer)
				if err != nil {
					log.Printf("failed to run tailscale up: %s", err)
				}

				err = s.runHeadscaleRegister(userStr, loginURL)
				if err != nil {
					log.Printf("failed to register client: %s", err)
				}
			}(client)

			err := client.WaitForReady()
			if err != nil {
				log.Printf("error waiting for client %s to be ready: %s", client.Hostname(), err)
			}
		}
		user.joinWaitGroup.Wait()

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
			[]string{"headscale", "-n", userStr, "nodes", "register", "--key", key},
		)
		if err != nil {
			log.Printf("failed to register node: %s", err)

			return err
		}

		return nil
	}

	return fmt.Errorf("failed to find headscale: %w", errNoHeadscaleAvailable)
}
