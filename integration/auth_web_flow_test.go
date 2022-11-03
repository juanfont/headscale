package integration

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog/log"
)

type AuthWebFlowScenario struct {
	*Scenario
}

func TestAuthWebFlowAuthenticationPingAll(t *testing.T) {
	IntegrationSkip(t)

	baseScenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario := AuthWebFlowScenario{
		Scenario: baseScenario,
	}

	spec := map[string]int{
		"namespace1": len(TailscaleVersions),
		"namespace2": len(TailscaleVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec)
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

func (s *AuthWebFlowScenario) CreateHeadscaleEnv(namespaces map[string]int) error {
	err := s.StartHeadscale()
	if err != nil {
		return err
	}

	err = s.Headscale().WaitForReady()
	if err != nil {
		return err
	}

	for namespaceName, clientCount := range namespaces {
		err = s.CreateNamespace(namespaceName)
		if err != nil {
			return err
		}

		err = s.CreateTailscaleNodesInNamespace(namespaceName, "all", clientCount)
		if err != nil {
			return err
		}

		err = s.runTailscaleUp(namespaceName, s.Headscale().GetEndpoint())
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *AuthWebFlowScenario) runTailscaleUp(
	namespaceStr, loginServer string,
) error {
	if namespace, ok := s.namespaces[namespaceStr]; ok {
		for _, client := range namespace.Clients {
			// namespace.joinWaitGroup.Add(1)

			// go func(c TailscaleClient) error {
			// defer namespace.joinWaitGroup.Done()

			// TODO(juanfont): error handle this

			loginURL, err := client.UpWithLoginURL(loginServer)
			if err != nil {
				return err
			}

			err = s.runHeadscaleRegister(namespaceStr, loginURL)
			if err != nil {
				return err
			}

			// }(client)
		}
		// namespace.joinWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to up tailscale node: %w", errNoNamespaceAvailable)
}

func (s *AuthWebFlowScenario) runHeadscaleRegister(namespaceStr string, loginURL *url.URL) error {
	log.Info().Msgf("loginURL: %s", loginURL)
	insecureTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: insecureTransport}

	resp, err := httpClient.Get(loginURL.String())
	if err != nil {
		return err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// see api.go HTML template
	key := strings.Split(strings.Split(string(body), "</code>")[0], "--key ")[1]
	if headscale, ok := s.controlServers["headscale"]; ok {
		_, err = headscale.Execute([]string{
			"headscale", "-n", namespaceStr, "register", "--key", key})
		if err != nil {
			return err
		}
	}

	return fmt.Errorf("failed to register client: %w", errNoHeadscaleAvailable)

}
