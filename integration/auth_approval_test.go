package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

type AuthApprovalScenario struct {
	*Scenario
}

func TestAuthNodeApproval(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	baseScenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)

	scenario := AuthApprovalScenario{
		Scenario: baseScenario,
	}
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"user1": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithTestName("approval"),
		hsic.WithTLS(),
		hsic.WithHostnameAsServerURL(),
		hsic.WithManualApproveNewNode(),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSyncWithPeerCount(0)
	assertNoErrSync(t, err)

	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)
		assert.Equal(t, "NeedsMachineAuth", status.BackendState)
		assert.Empty(t, status.Peers())
	}

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	var allNodes []*v1.Node
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		&allNodes,
	)
	assertNoErr(t, err)

	for _, node := range allNodes {
		_, err = headscale.Execute([]string{
			"headscale", "nodes", "approve", "--identifier", strconv.FormatUint(node.GetId(), 10),
		})
		assertNoErr(t, err)
	}

	for _, client := range allClients {
		err = client.Logout()
		if err != nil {
			t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	err = scenario.WaitForTailscaleLogout()
	assertNoErrLogout(t, err)

	t.Logf("all clients logged out")

	for userName := range spec {
		err = scenario.runTailscaleUp(userName, headscale.GetEndpoint(), true)
		if err != nil {
			t.Fatalf("failed to run tailscale up: %s", err)
		}
	}

	t.Logf("all clients logged in again")

	allClients, err = scenario.ListTailscaleClients()
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
	t.Logf("before expire: %d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		// Assert that we have the original count - self
		assert.Len(t, status.Peers(), len(MustTestVersions)-1)
	}
}

func (s *AuthApprovalScenario) CreateHeadscaleEnv(
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

		err = s.runTailscaleUp(userName, headscale.GetEndpoint(), false)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *AuthApprovalScenario) runTailscaleUp(
	userStr, loginServer string,
	withApproved bool,
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

			if withApproved {
				err := client.WaitForRunning()
				if err != nil {
					log.Printf("error waiting for client %s to be approval: %s", client.Hostname(), err)
				}
			} else {
				err := client.WaitForNeedsApprove()
				if err != nil {
					log.Printf("error waiting for client %s to be approval: %s", client.Hostname(), err)
				}
			}
		}

		if err := user.joinWaitGroup.Wait(); err != nil {
			return err
		}

		for _, client := range user.Clients {
			if withApproved {
				err := client.WaitForRunning()
				if err != nil {
					return fmt.Errorf("%s failed to up tailscale node: %w", client.Hostname(), err)
				}
			} else {
				err := client.WaitForNeedsApprove()
				if err != nil {
					return fmt.Errorf("%s failed to up tailscale node: %w", client.Hostname(), err)
				}
			}
		}

		return nil
	}

	return fmt.Errorf("failed to up tailscale node: %w", errNoUserAvailable)
}

func (s *AuthApprovalScenario) runHeadscaleRegister(userStr string, loginURL *url.URL) error {
	headscale, err := s.Headscale()
	if err != nil {
		return err
	}

	log.Printf("loginURL: %s", loginURL)
	loginURL.Host = fmt.Sprintf("%s:%d", headscale.GetIP(), 8080)
	loginURL.Scheme = types.SchemaHTTP

	if len(headscale.GetCert()) > 0 {
		loginURL.Scheme = types.SchemaHTTPS
	}

	insecureTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint
	}
	httpClient := &http.Client{
		Transport: insecureTransport,
	}
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
