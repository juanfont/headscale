package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
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

func (s *AuthWebFlowScenario) CreateHeadscaleEnv(
	namespaces map[string]int,
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

	for namespaceName, clientCount := range namespaces {
		log.Printf("creating namespace %s with %d clients", namespaceName, clientCount)
		err = s.CreateNamespace(namespaceName)
		if err != nil {
			return err
		}

		err = s.CreateTailscaleNodesInNamespace(namespaceName, "all", clientCount)
		if err != nil {
			return err
		}

		err = s.runTailscaleUp(namespaceName, headscale.GetEndpoint())
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *AuthWebFlowScenario) runTailscaleUp(
	namespaceStr, loginServer string,
) error {
	log.Printf("running tailscale up for namespace %s", namespaceStr)
	if namespace, ok := s.namespaces[namespaceStr]; ok {
		for _, client := range namespace.Clients {
			namespace.joinWaitGroup.Add(1)

			go func(c TailscaleClient) {
				defer namespace.joinWaitGroup.Done()

				// TODO(juanfont): error handle this
				loginURL, err := c.UpWithLoginURL(loginServer)
				if err != nil {
					log.Printf("failed to run tailscale up: %s", err)
				}

				err = s.runHeadscaleRegister(namespaceStr, loginURL)
				if err != nil {
					log.Printf("failed to register client: %s", err)
				}
			}(client)

			err := client.WaitForReady()
			if err != nil {
				log.Printf("error waiting for client %s to be ready: %s", client.Hostname(), err)
			}
		}
		namespace.joinWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to up tailscale node: %w", errNoNamespaceAvailable)
}

func (s *AuthWebFlowScenario) runHeadscaleRegister(namespaceStr string, loginURL *url.URL) error {
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
			[]string{"headscale", "-n", namespaceStr, "nodes", "register", "--key", key},
		)
		if err != nil {
			log.Printf("failed to register node: %s", err)

			return err
		}

		return nil
	}

	return fmt.Errorf("failed to find headscale: %w", errNoHeadscaleAvailable)
}
