package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/oauth2-proxy/mockoidc"
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
	defer scenario.ShutdownAssertNoPanics(t)

	// Logins to MockOIDC is served by a queue with a strict order,
	// if we use more than one node per user, the order of the logins
	// will not be deterministic and the test will fail.
	spec := map[string]int{
		"user1": 1,
		"user2": 1,
	}

	mockusers := []mockoidc.MockUser{
		oidcMockUser("user1", true),
		oidcMockUser("user2", false),
	}

	oidcConfig, err := scenario.runMockOIDC(defaultAccessTTL, mockusers)
	assertNoErrf(t, "failed to run mock OIDC server: %s", err)
	defer scenario.mockOIDC.Close()

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             oidcConfig.Issuer,
		"HEADSCALE_OIDC_CLIENT_ID":          oidcConfig.ClientID,
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
		// TODO(kradalby): Remove when strip_email_domain is removed
		// after #2170 is cleaned up
		"HEADSCALE_OIDC_MAP_LEGACY_USERS":   "0",
		"HEADSCALE_OIDC_STRIP_EMAIL_DOMAIN": "0",
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithTestName("oidcauthping"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithTLS(),
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

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	var listUsers []v1.User
	err = executeAndUnmarshal(headscale,
		[]string{
			"headscale",
			"users",
			"list",
			"--output",
			"json",
		},
		&listUsers,
	)
	assertNoErr(t, err)

	want := []v1.User{
		{
			Id:    1,
			Name:  "user1",
			Email: "user1@test.no",
		},
		{
			Id:         2,
			Name:       "user1",
			Email:      "user1@headscale.net",
			Provider:   "oidc",
			ProviderId: oidcConfig.Issuer + "/user1",
		},
		{
			Id:    3,
			Name:  "user2",
			Email: "user2@test.no",
		},
		{
			Id:         4,
			Name:       "user2",
			Email:      "", // Unverified
			Provider:   "oidc",
			ProviderId: oidcConfig.Issuer + "/user2",
		},
	}

	sort.Slice(listUsers, func(i, j int) bool {
		return listUsers[i].GetId() < listUsers[j].GetId()
	})

	if diff := cmp.Diff(want, listUsers, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
		t.Fatalf("unexpected users: %s", diff)
	}
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
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"user1": 1,
		"user2": 1,
	}

	oidcConfig, err := scenario.runMockOIDC(shortAccessTTL, []mockoidc.MockUser{
		oidcMockUser("user1", true),
		oidcMockUser("user2", false),
	})
	assertNoErrf(t, "failed to run mock OIDC server: %s", err)
	defer scenario.mockOIDC.Close()

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":                oidcConfig.Issuer,
		"HEADSCALE_OIDC_CLIENT_ID":             oidcConfig.ClientID,
		"HEADSCALE_OIDC_CLIENT_SECRET":         oidcConfig.ClientSecret,
		"HEADSCALE_OIDC_USE_EXPIRY_FROM_TOKEN": "1",
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithTestName("oidcexpirenodes"),
		hsic.WithConfigEnv(oidcMap),
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

// TODO(kradalby):
// - Test that creates a new user when one exists when migration is turned off
// - Test that takes over a user when one exists when migration is turned on
//   - But email is not verified
//   - stripped email domain on/off
func TestOIDC024UserCreation(t *testing.T) {
	IntegrationSkip(t)

	tests := []struct {
		name          string
		config        map[string]string
		emailVerified bool
		cliUsers      []string
		oidcUsers     []string
		want          func(iss string) []v1.User
	}{
		{
			name: "no-migration-verified-email",
			config: map[string]string{
				"HEADSCALE_OIDC_MAP_LEGACY_USERS": "0",
			},
			emailVerified: true,
			cliUsers:      []string{"user1", "user2"},
			oidcUsers:     []string{"user1", "user2"},
			want: func(iss string) []v1.User {
				return []v1.User{
					{
						Id:    1,
						Name:  "user1",
						Email: "user1@test.no",
					},
					{
						Id:         2,
						Name:       "user1",
						Email:      "user1@headscale.net",
						Provider:   "oidc",
						ProviderId: iss + "/user1",
					},
					{
						Id:    3,
						Name:  "user2",
						Email: "user2@test.no",
					},
					{
						Id:         4,
						Name:       "user2",
						Email:      "user2@headscale.net",
						Provider:   "oidc",
						ProviderId: iss + "/user2",
					},
				}
			},
		},
		{
			name: "no-migration-not-verified-email",
			config: map[string]string{
				"HEADSCALE_OIDC_MAP_LEGACY_USERS": "0",
			},
			emailVerified: false,
			cliUsers:      []string{"user1", "user2"},
			oidcUsers:     []string{"user1", "user2"},
			want: func(iss string) []v1.User {
				return []v1.User{
					{
						Id:    1,
						Name:  "user1",
						Email: "user1@test.no",
					},
					{
						Id:         2,
						Name:       "user1",
						Provider:   "oidc",
						ProviderId: iss + "/user1",
					},
					{
						Id:    3,
						Name:  "user2",
						Email: "user2@test.no",
					},
					{
						Id:         4,
						Name:       "user2",
						Provider:   "oidc",
						ProviderId: iss + "/user2",
					},
				}
			},
		},
		{
			name: "migration-strip-domains-verified-email",
			config: map[string]string{
				"HEADSCALE_OIDC_MAP_LEGACY_USERS":   "1",
				"HEADSCALE_OIDC_STRIP_EMAIL_DOMAIN": "1",
			},
			emailVerified: true,
			cliUsers:      []string{"user1", "user2"},
			oidcUsers:     []string{"user1", "user2"},
			want: func(iss string) []v1.User {
				return []v1.User{
					{
						Id:         1,
						Name:       "user1",
						Email:      "user1@headscale.net",
						Provider:   "oidc",
						ProviderId: iss + "/user1",
					},
					{
						Id:         2,
						Name:       "user2",
						Email:      "user2@headscale.net",
						Provider:   "oidc",
						ProviderId: iss + "/user2",
					},
				}
			},
		},
		{
			name: "migration-strip-domains-not-verified-email",
			config: map[string]string{
				"HEADSCALE_OIDC_MAP_LEGACY_USERS":   "1",
				"HEADSCALE_OIDC_STRIP_EMAIL_DOMAIN": "1",
			},
			emailVerified: false,
			cliUsers:      []string{"user1", "user2"},
			oidcUsers:     []string{"user1", "user2"},
			want: func(iss string) []v1.User {
				return []v1.User{
					{
						Id:    1,
						Name:  "user1",
						Email: "user1@test.no",
					},
					{
						Id:         2,
						Name:       "user1",
						Provider:   "oidc",
						ProviderId: iss + "/user1",
					},
					{
						Id:    3,
						Name:  "user2",
						Email: "user2@test.no",
					},
					{
						Id:         4,
						Name:       "user2",
						Provider:   "oidc",
						ProviderId: iss + "/user2",
					},
				}
			},
		},
		{
			name: "migration-no-strip-domains-verified-email",
			config: map[string]string{
				"HEADSCALE_OIDC_MAP_LEGACY_USERS":   "1",
				"HEADSCALE_OIDC_STRIP_EMAIL_DOMAIN": "0",
			},
			emailVerified: true,
			cliUsers:      []string{"user1.headscale.net", "user2.headscale.net"},
			oidcUsers:     []string{"user1", "user2"},
			want: func(iss string) []v1.User {
				return []v1.User{
					// Hmm I think we will have to overwrite the initial name here
					// createuser with "user1.headscale.net", but oidc with "user1"
					{
						Id:         1,
						Name:       "user1",
						Email:      "user1@headscale.net",
						Provider:   "oidc",
						ProviderId: iss + "/user1",
					},
					{
						Id:         2,
						Name:       "user2",
						Email:      "user2@headscale.net",
						Provider:   "oidc",
						ProviderId: iss + "/user2",
					},
				}
			},
		},
		{
			name: "migration-no-strip-domains-not-verified-email",
			config: map[string]string{
				"HEADSCALE_OIDC_MAP_LEGACY_USERS":   "1",
				"HEADSCALE_OIDC_STRIP_EMAIL_DOMAIN": "0",
			},
			emailVerified: false,
			cliUsers:      []string{"user1.headscale.net", "user2.headscale.net"},
			oidcUsers:     []string{"user1", "user2"},
			want: func(iss string) []v1.User {
				return []v1.User{
					{
						Id:    1,
						Name:  "user1.headscale.net",
						Email: "user1.headscale.net@test.no",
					},
					{
						Id:         2,
						Name:       "user1",
						Provider:   "oidc",
						ProviderId: iss + "/user1",
					},
					{
						Id:    3,
						Name:  "user2.headscale.net",
						Email: "user2.headscale.net@test.no",
					},
					{
						Id:         4,
						Name:       "user2",
						Provider:   "oidc",
						ProviderId: iss + "/user2",
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseScenario, err := NewScenario(dockertestMaxWait())
			assertNoErr(t, err)

			scenario := AuthOIDCScenario{
				Scenario: baseScenario,
			}
			defer scenario.ShutdownAssertNoPanics(t)

			spec := map[string]int{}
			for _, user := range tt.cliUsers {
				spec[user] = 1
			}

			var mockusers []mockoidc.MockUser
			for _, user := range tt.oidcUsers {
				mockusers = append(mockusers, oidcMockUser(user, tt.emailVerified))
			}

			oidcConfig, err := scenario.runMockOIDC(defaultAccessTTL, mockusers)
			assertNoErrf(t, "failed to run mock OIDC server: %s", err)
			defer scenario.mockOIDC.Close()

			oidcMap := map[string]string{
				"HEADSCALE_OIDC_ISSUER":             oidcConfig.Issuer,
				"HEADSCALE_OIDC_CLIENT_ID":          oidcConfig.ClientID,
				"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
				"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
			}

			for k, v := range tt.config {
				oidcMap[k] = v
			}

			err = scenario.CreateHeadscaleEnv(
				spec,
				hsic.WithTestName("oidcmigration"),
				hsic.WithConfigEnv(oidcMap),
				hsic.WithTLS(),
				hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(oidcConfig.ClientSecret)),
			)
			assertNoErrHeadscaleEnv(t, err)

			// Ensure that the nodes have logged in, this is what
			// triggers user creation via OIDC.
			err = scenario.WaitForTailscaleSync()
			assertNoErrSync(t, err)

			headscale, err := scenario.Headscale()
			assertNoErr(t, err)

			want := tt.want(oidcConfig.Issuer)

			var listUsers []v1.User
			err = executeAndUnmarshal(headscale,
				[]string{
					"headscale",
					"users",
					"list",
					"--output",
					"json",
				},
				&listUsers,
			)
			assertNoErr(t, err)

			sort.Slice(listUsers, func(i, j int) bool {
				return listUsers[i].GetId() < listUsers[j].GetId()
			})

			if diff := cmp.Diff(want, listUsers, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
				t.Errorf("unexpected users: %s", diff)
			}
		})
	}
}

func TestOIDCAuthenticationWithPKCE(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	baseScenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)

	scenario := AuthOIDCScenario{
		Scenario: baseScenario,
	}
	defer scenario.ShutdownAssertNoPanics(t)

	// Single user with one node for testing PKCE flow
	spec := map[string]int{
		"user1": 1,
	}

	mockusers := []mockoidc.MockUser{
		oidcMockUser("user1", true),
	}

	oidcConfig, err := scenario.runMockOIDC(defaultAccessTTL, mockusers)
	assertNoErrf(t, "failed to run mock OIDC server: %s", err)
	defer scenario.mockOIDC.Close()

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             oidcConfig.Issuer,
		"HEADSCALE_OIDC_CLIENT_ID":          oidcConfig.ClientID,
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_PKCE_ENABLED":       "1", // Enable PKCE
		"HEADSCALE_OIDC_MAP_LEGACY_USERS":   "0",
		"HEADSCALE_OIDC_STRIP_EMAIL_DOMAIN": "0",
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithTestName("oidcauthpkce"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithTLS(),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(oidcConfig.ClientSecret)),
	)
	assertNoErrHeadscaleEnv(t, err)

	// Get all clients and verify they can connect
	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// Verify PKCE was used in authentication
	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	var listUsers []v1.User
	err = executeAndUnmarshal(headscale,
		[]string{
			"headscale",
			"users",
			"list",
			"--output",
			"json",
		},
		&listUsers,
	)
	assertNoErr(t, err)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
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
		if clientCount != 1 {
			// OIDC scenario only supports one client per user.
			// This is because the MockOIDC server can only serve login
			// requests based on a queue it has been given on startup.
			// We currently only populates it with one login request per user.
			return fmt.Errorf("client count must be 1 for OIDC scenario.")
		}
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

func (s *AuthOIDCScenario) runMockOIDC(accessTTL time.Duration, users []mockoidc.MockUser) (*types.OIDCConfig, error) {
	port, err := dockertestutil.RandomFreeHostPort()
	if err != nil {
		log.Fatalf("could not find an open port: %s", err)
	}
	portNotation := fmt.Sprintf("%d/tcp", port)

	hash, _ := util.GenerateRandomStringDNSSafe(hsicOIDCMockHashLength)

	hostname := fmt.Sprintf("hs-oidcmock-%s", hash)

	usersJSON, err := json.Marshal(users)
	if err != nil {
		return nil, err
	}

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
			fmt.Sprintf("MOCKOIDC_USERS=%s", string(usersJSON)),
		},
	}

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: hsic.IntegrationTestDockerFileName,
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
		OnlyStartIfOIDCIsAvailable: true,
	}, nil
}

type LoggingRoundTripper struct{}

func (t LoggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	noTls := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint
	}
	resp, err := noTls.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	log.Printf("---")
	log.Printf("method: %s | url: %s", resp.Request.Method, resp.Request.URL.String())
	log.Printf("status: %d | cookies: %+v", resp.StatusCode, resp.Cookies())

	return resp, nil
}

func (s *AuthOIDCScenario) runTailscaleUp(
	userStr, loginServer string,
) error {
	log.Printf("running tailscale up for user %s", userStr)
	if user, ok := s.users[userStr]; ok {
		for _, client := range user.Clients {
			tsc := client
			user.joinWaitGroup.Go(func() error {
				loginURL, err := tsc.LoginWithURL(loginServer)
				if err != nil {
					log.Printf("%s failed to run tailscale up: %s", tsc.Hostname(), err)
				}

				_, err = doLoginURL(tsc.Hostname(), loginURL)
				if err != nil {
					return err
				}

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

// doLoginURL visits the given login URL and returns the body as a
// string.
func doLoginURL(hostname string, loginURL *url.URL) (string, error) {
	log.Printf("%s login url: %s\n", hostname, loginURL.String())

	var err error
	hc := &http.Client{
		Transport: LoggingRoundTripper{},
	}
	hc.Jar, err = cookiejar.New(nil)
	if err != nil {
		return "", fmt.Errorf("%s failed to create cookiejar	: %w", hostname, err)
	}

	log.Printf("%s logging in with url", hostname)
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, loginURL.String(), nil)
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s failed to send http request: %w", hostname, err)
	}

	log.Printf("cookies: %+v", hc.Jar.Cookies(loginURL))

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("body: %s", body)

		return "", fmt.Errorf("%s response code of login request was %w", hostname, err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("%s failed to read response body: %s", hostname, err)

		return "", fmt.Errorf("%s failed to read response body: %w", hostname, err)
	}

	return string(body), nil
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

func oidcMockUser(username string, emailVerified bool) mockoidc.MockUser {
	return mockoidc.MockUser{
		Subject:           username,
		PreferredUsername: username,
		Email:             fmt.Sprintf("%s@headscale.net", username),
		EmailVerified:     emailVerified,
	}
}
