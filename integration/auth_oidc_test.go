package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"

	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const (
	dockerContextPath      = "../."
	hsicOIDCMockHashLength = 6
)

type AuthOIDCScenario struct {
	*Scenario

	mockOIDC *dockertest.Resource
}

func TestOIDCAuthenticationPingAll(t *testing.T) {
	IntegrationSkip(t)

	baseScenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario := AuthOIDCScenario{
		Scenario: baseScenario,
	}

	spec := map[string]int{
		"namespace1": len(TailscaleVersions),
	}

	oidcConfig, err := scenario.runMockOIDC()
	if err != nil {
		t.Errorf("failed to run mock OIDC server: %s", err)
	}

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             oidcConfig.Issuer,
		"HEADSCALE_OIDC_CLIENT_ID":          oidcConfig.ClientID,
		"HEADSCALE_OIDC_CLIENT_SECRET":      oidcConfig.ClientSecret,
		"HEADSCALE_OIDC_STRIP_EMAIL_DOMAIN": fmt.Sprintf("%t", oidcConfig.StripEmaildomain),
		"ONLY_START_IF_OIDC_IS_AVAILABLE":   "true",
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithTestName("oidcauthping"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithHostnameAsServerURL(),
	)
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

func (s *AuthOIDCScenario) CreateHeadscaleEnv(
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

func (s *AuthOIDCScenario) runMockOIDC() (*headscale.OIDCConfig, error) {
	hash, _ := headscale.GenerateRandomStringDNSSafe(hsicOIDCMockHashLength)

	hostname := fmt.Sprintf("hs-oidcmock-%s", hash)

	mockOidcOptions := &dockertest.RunOptions{
		Name:         hostname,
		Cmd:          []string{"headscale", "mockoidc"},
		ExposedPorts: []string{"10000/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"10000/tcp": {{HostPort: "10000"}},
		},
		Networks: []*dockertest.Network{s.Scenario.network},
		Env: []string{
			fmt.Sprintf("MOCKOIDC_ADDR=%s", hostname),
			"MOCKOIDC_PORT=10000",
			"MOCKOIDC_CLIENT_ID=superclient",
			"MOCKOIDC_CLIENT_SECRET=supersecret",
		},
	}

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile.debug",
		ContextDir: dockerContextPath,
	}

	err := s.pool.RemoveContainerByName(hostname)
	if err != nil {
		return nil, err
	}

	if pmockoidc, err := s.pool.BuildAndRunWithBuildOptions(
		headscaleBuildOptions,
		mockOidcOptions,
		dockertestutil.DockerRestartPolicy); err == nil {
		s.mockOIDC = pmockoidc
	} else {
		return nil, err
	}

	log.Println("Waiting for headscale mock oidc to be ready for tests")
	hostEndpoint := fmt.Sprintf(
		"%s:%s",
		s.mockOIDC.GetIPInNetwork(s.network),
		s.mockOIDC.GetPort("10000/tcp"),
	)

	if err := s.pool.Retry(func() error {
		url := fmt.Sprintf("http://%s/oidc/.well-known/openid-configuration", hostEndpoint)
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("headscale mock OIDC tests is not ready: %s\n", err)
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status code not OK")
		}

		return nil
	}); err != nil {
		return nil, err
	}

	log.Printf("headscale mock oidc is ready for tests at %s", hostEndpoint)

	return &headscale.OIDCConfig{
		Issuer:           fmt.Sprintf("http://%s:10000/oidc", s.mockOIDC.GetIPInNetwork(s.network)),
		ClientID:         "superclient",
		ClientSecret:     "supersecret",
		StripEmaildomain: true,
	}, nil
}

func (s *AuthOIDCScenario) runTailscaleUp(
	namespaceStr, loginServer string,
) error {
	headscale, err := s.Headscale()
	if err != nil {
		return err
	}

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

				loginURL.Host = fmt.Sprintf("%s:8080", headscale.GetIP())
				loginURL.Scheme = "http"

				insecureTransport := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}

				fmt.Printf("login url: %s\n", loginURL.String())

				httpClient := &http.Client{Transport: insecureTransport}
				ctx := context.Background()
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, loginURL.String(), nil)
				resp, err := httpClient.Do(req)
				if err != nil {
					log.Printf("failed to get login url: %s", err)
					return
				}

				_, err = io.ReadAll(resp.Body)
				if err != nil {
					log.Printf("failed to read response body: %s", err)
					return
				}

				err = c.WaitForReady()
				if err != nil {
					log.Printf("error waiting for client %s to be ready: %s", c.Hostname(), err)
				}
			}(client)
		}
		namespace.joinWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to up tailscale node: %w", errNoNamespaceAvailable)
}

func (s *AuthOIDCScenario) Shutdown() error {
	err := s.pool.Purge(s.mockOIDC)
	if err != nil {
		return err
	}

	return s.Scenario.Shutdown()
}
