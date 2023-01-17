package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const (
	dockerContextPath      = "../."
	hsicOIDCMockHashLength = 6
	defaultAccessTTL       = 10 * time.Minute
)

var errStatusCodeNotOK = errors.New("status code not OK")

type AuthOIDCScenario struct {
	*Scenario

	mockOIDC *dockertest.Resource
}

func TestOIDCAuthenticationPingAll(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	baseScenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario := AuthOIDCScenario{
		Scenario: baseScenario,
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions),
	}

	oidcConfig, err := scenario.runMockOIDC(defaultAccessTTL)
	if err != nil {
		t.Errorf("failed to run mock OIDC server: %s", err)
	}

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             oidcConfig.Issuer,
		"HEADSCALE_OIDC_CLIENT_ID":          oidcConfig.ClientID,
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
		"HEADSCALE_OIDC_STRIP_EMAIL_DOMAIN": fmt.Sprintf("%t", oidcConfig.StripEmaildomain),
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithTestName("oidcauthping"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithHostnameAsServerURL(),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(oidcConfig.ClientSecret)),
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

	success := pingAll(t, allClients, allIps)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestOIDCExpireNodes(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	shortAccessTTL := 5 * time.Minute

	baseScenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario := AuthOIDCScenario{
		Scenario: baseScenario,
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions),
	}

	oidcConfig, err := scenario.runMockOIDC(shortAccessTTL)
	if err != nil {
		t.Fatalf("failed to run mock OIDC server: %s", err)
	}

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             oidcConfig.Issuer,
		"HEADSCALE_OIDC_CLIENT_ID":          oidcConfig.ClientID,
		"HEADSCALE_OIDC_CLIENT_SECRET":      oidcConfig.ClientSecret,
		"HEADSCALE_OIDC_STRIP_EMAIL_DOMAIN": fmt.Sprintf("%t", oidcConfig.StripEmaildomain),
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithTestName("oidcexpirenodes"),
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

	success := pingAll(t, allClients, allIps)
	t.Logf("%d successful pings out of %d (before expiry)", success, len(allClients)*len(allIps))

	// await all nodes being logged out after OIDC token expiry
	scenario.WaitForTailscaleLogout()

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func (s *AuthOIDCScenario) CreateHeadscaleEnv(
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

func (s *AuthOIDCScenario) runMockOIDC(accessTTL time.Duration) (*headscale.OIDCConfig, error) {
	port, err := dockertestutil.RandomFreeHostPort()
	if err != nil {
		log.Fatalf("could not find an open port: %s", err)
	}
	portNotation := fmt.Sprintf("%d/tcp", port)

	hash, _ := headscale.GenerateRandomStringDNSSafe(hsicOIDCMockHashLength)

	hostname := fmt.Sprintf("hs-oidcmock-%s", hash)

	mockOidcOptions := &dockertest.RunOptions{
		Name:         hostname,
		Cmd:          []string{"headscale", "mockoidc"},
		ExposedPorts: []string{portNotation},
		PortBindings: map[docker.Port][]docker.PortBinding{
			docker.Port(portNotation): {{HostPort: strconv.Itoa(port)}},
		},
		Networks: []*dockertest.Network{s.Scenario.network},
		Env: []string{
			fmt.Sprintf("MOCKOIDC_ADDR=%s", hostname),
			fmt.Sprintf("MOCKOIDC_PORT=%d", port),
			"MOCKOIDC_CLIENT_ID=superclient",
			"MOCKOIDC_CLIENT_SECRET=supersecret",
			fmt.Sprintf("MOCKOIDC_ACCESS_TTL=%s", accessTTL.String()),
		},
	}

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile.debug",
		ContextDir: dockerContextPath,
	}

	err = s.pool.RemoveContainerByName(hostname)
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
	hostEndpoint := fmt.Sprintf("%s:%d", s.mockOIDC.GetIPInNetwork(s.network), port)

	if err := s.pool.Retry(func() error {
		oidcConfigURL := fmt.Sprintf("http://%s/oidc/.well-known/openid-configuration", hostEndpoint)
		httpClient := &http.Client{}
		ctx := context.Background()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, oidcConfigURL, nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			log.Printf("headscale mock OIDC tests is not ready: %s\n", err)

			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return errStatusCodeNotOK
		}

		return nil
	}); err != nil {
		return nil, err
	}

	log.Printf("headscale mock oidc is ready for tests at %s", hostEndpoint)

	return &headscale.OIDCConfig{
		Issuer:                     fmt.Sprintf("http://%s/oidc", net.JoinHostPort(s.mockOIDC.GetIPInNetwork(s.network), strconv.Itoa(port))),
		ClientID:                   "superclient",
		ClientSecret:               "supersecret",
		StripEmaildomain:           true,
		OnlyStartIfOIDCIsAvailable: true,
	}, nil
}

func (s *AuthOIDCScenario) runTailscaleUp(
	userStr, loginServer string,
) error {
	headscale, err := s.Headscale()
	if err != nil {
		return err
	}

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

				loginURL.Host = fmt.Sprintf("%s:8080", headscale.GetIP())
				loginURL.Scheme = "http"

				insecureTransport := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint
				}

				log.Printf("%s login url: %s\n", c.Hostname(), loginURL.String())

				httpClient := &http.Client{Transport: insecureTransport}
				ctx := context.Background()
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, loginURL.String(), nil)
				resp, err := httpClient.Do(req)
				if err != nil {
					log.Printf("%s failed to get login url %s: %s", c.Hostname(), loginURL, err)

					return
				}

				defer resp.Body.Close()

				_, err = io.ReadAll(resp.Body)
				if err != nil {
					log.Printf("%s failed to read response body: %s", c.Hostname(), err)

					return
				}

				log.Printf("Finished request for %s to join tailnet", c.Hostname())
			}(client)

			err = client.WaitForReady()
			if err != nil {
				log.Printf("error waiting for client %s to be ready: %s", client.Hostname(), err)
			}

			log.Printf("client %s is ready", client.Hostname())
		}

		user.joinWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to up tailscale node: %w", errNoUserAvailable)
}

func pingAll(t *testing.T, clients []TailscaleClient, ips []netip.Addr) int {
	t.Helper()
	success := 0

	for _, client := range clients {
		for _, ip := range ips {
			err := client.Ping(ip.String())
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", ip, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	return success
}

func (s *AuthOIDCScenario) Shutdown() error {
	err := s.pool.Purge(s.mockOIDC)
	if err != nil {
		return err
	}

	return s.Scenario.Shutdown()
}
