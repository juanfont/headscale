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

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
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

	baseScenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)

	scenario := AuthOIDCScenario{
		Scenario: baseScenario,
	}
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": len(MustTestVersions),
	}

	oidcConfig, err := scenario.runMockOIDC(defaultAccessTTL)
	assertNoErrf(t, "failed to run mock OIDC server: %s", err)

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

// This test is really flaky.
func TestOIDCExpireNodesBasedOnTokenExpiry(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	shortAccessTTL := 5 * time.Minute

	baseScenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)

	baseScenario.pool.MaxWait = 5 * time.Minute

	scenario := AuthOIDCScenario{
		Scenario: baseScenario,
	}
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": 3,
	}

	oidcConfig, err := scenario.runMockOIDC(shortAccessTTL)
	assertNoErrf(t, "failed to run mock OIDC server: %s", err)

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":                oidcConfig.Issuer,
		"HEADSCALE_OIDC_CLIENT_ID":             oidcConfig.ClientID,
		"HEADSCALE_OIDC_CLIENT_SECRET":         oidcConfig.ClientSecret,
		"HEADSCALE_OIDC_STRIP_EMAIL_DOMAIN":    fmt.Sprintf("%t", oidcConfig.StripEmaildomain),
		"HEADSCALE_OIDC_USE_EXPIRY_FROM_TOKEN": "1",
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithTestName("oidcexpirenodes"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithHostnameAsServerURL(),
	)
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
	t.Logf("%d successful pings out of %d (before expiry)", success, len(allClients)*len(allIps))

	// This is not great, but this sadly is a time dependent test, so the
	// safe thing to do is wait out the whole TTL time before checking if
	// the clients have logged out. The Wait function cant do it itself
	// as it has an upper bound of 1 min.
	time.Sleep(shortAccessTTL)

	assertTailscaleNodesLogout(t, allClients)
}

func (s *AuthOIDCScenario) CreateHeadscaleEnv(
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

func (s *AuthOIDCScenario) runMockOIDC(accessTTL time.Duration) (*types.OIDCConfig, error) {
	port, err := dockertestutil.RandomFreeHostPort()
	if err != nil {
		log.Fatalf("could not find an open port: %s", err)
	}
	portNotation := fmt.Sprintf("%d/tcp", port)

	hash, _ := util.GenerateRandomStringDNSSafe(hsicOIDCMockHashLength)

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

	return &types.OIDCConfig{
		Issuer: fmt.Sprintf(
			"http://%s/oidc",
			net.JoinHostPort(s.mockOIDC.GetIPInNetwork(s.network), strconv.Itoa(port)),
		),
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
			c := client
			user.joinWaitGroup.Go(func() error {
				loginURL, err := c.LoginWithURL(loginServer)
				if err != nil {
					log.Printf("%s failed to run tailscale up: %s", c.Hostname(), err)
				}

				loginURL.Host = fmt.Sprintf("%s:8080", headscale.GetIP())
				loginURL.Scheme = "http"

				insecureTransport := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint
				}

				log.Printf("%s login url: %s\n", c.Hostname(), loginURL.String())

				if err := s.pool.Retry(func() error {
					log.Printf("%s logging in with url", c.Hostname())
					httpClient := &http.Client{Transport: insecureTransport}
					ctx := context.Background()
					req, _ := http.NewRequestWithContext(ctx, http.MethodGet, loginURL.String(), nil)
					resp, err := httpClient.Do(req)
					if err != nil {
						log.Printf(
							"%s failed to login using url %s: %s",
							c.Hostname(),
							loginURL,
							err,
						)

						return err
					}

					if resp.StatusCode != http.StatusOK {
						log.Printf("%s response code of oidc login request was %s", c.Hostname(), resp.Status)

						return errStatusCodeNotOK
					}

					defer resp.Body.Close()

					_, err = io.ReadAll(resp.Body)
					if err != nil {
						log.Printf("%s failed to read response body: %s", c.Hostname(), err)

						return err
					}

					return nil
				}); err != nil {
					return err
				}

				log.Printf("Finished request for %s to join tailnet", c.Hostname())

				return nil
			})

			log.Printf("client %s is ready", client.Hostname())
		}

		if err := user.joinWaitGroup.Wait(); err != nil {
			return err
		}

		for _, client := range user.Clients {
			err := client.WaitForRunning()
			if err != nil {
				return fmt.Errorf(
					"%s tailscale node has not reached running: %w",
					client.Hostname(),
					err,
				)
			}
		}

		return nil
	}

	return fmt.Errorf("failed to up tailscale node: %w", errNoUserAvailable)
}

func (s *AuthOIDCScenario) Shutdown() {
	err := s.pool.Purge(s.mockOIDC)
	if err != nil {
		log.Printf("failed to remove mock oidc container")
	}

	s.Scenario.Shutdown()
}

func assertTailscaleNodesLogout(t *testing.T, clients []TailscaleClient) {
	t.Helper()

	for _, client := range clients {
		status, err := client.Status()
		assertNoErr(t, err)

		assert.Equal(t, "NeedsLogin", status.BackendState)
	}
}
