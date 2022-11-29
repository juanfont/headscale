package integration

import (
	"fmt"
	"testing"
	"net/http"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
)



func executeGoodRequest(t * testing.T, endpoint string, reqContent string) bool {
	rsp, err := http.Get(fmt.Sprintf("%s/%s", endpoint, reqContent))	
	if err != nil {
		t.Errorf("Failed to run test: %s | err: %s", reqContent, err)
		return false
	} else {
		if rsp.StatusCode != 200 {
			t.Errorf("Request that should have succeeded returned unexpected status code | req: %s/%s | code: %d", endpoint, reqContent, rsp.StatusCode)
			return false 
		} else {
			return true
		}
	}
}

func executeBadRequest(t * testing.T, endpoint string, reqContent string) bool {
	rsp, err := http.Get(fmt.Sprintf("%s/%s", endpoint, reqContent))	
	if err != nil {
		t.Errorf("Failed to run test: %s | err: %s", reqContent, err)
		return false
	} else {
		if (rsp.StatusCode == 200) {
			t.Errorf("Request that should have failed returned successful status code | req: %s/%s | code: %d", endpoint, reqContent, rsp.StatusCode)
			return false 
		} else {
			return true
		}
	}
}

func TestRouterPaths(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
	//	"namespace1": len(TailscaleVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("testrouterpaths"))
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	headscale, err := scenario.Headscale()
	if err != nil {
		t.Errorf("could not get headscale instance from scenario: %s", err)
	}

	successes := 0
	var should_succeed  = []string {
		"register/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}



	for _, req := range should_succeed {
		if executeGoodRequest(t, headscale.GetEndpoint(), req) {
			successes++
		}
	}
	t.Logf("%d should-succeed requests succeeded, out of %d", successes, len(should_succeed))

	var should_fail = []string {
		"rogister/abcd",
		"register/abcd/",
		"register/abcdj",
	}

	failures := 0 
	for _, req := range should_fail {
		if executeBadRequest(t, headscale.GetEndpoint(), req) {
			failures++
		}
	}
	t.Logf("%d should-fail requests failed, out of %d", failures, len(should_fail))


	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}