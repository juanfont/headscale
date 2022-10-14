package integration

import (
	"testing"

	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/tsic"
)

func IntegrationSkip(t *testing.T) {
	t.Helper()

	if !dockertestutil.IsRunningInContainer() {
		t.Skip("not running in docker, skipping")
	}

	if testing.Short() {
		t.Skip("skipping integration tests due to short flag")
	}
}

func TestHeadscale(t *testing.T) {
	IntegrationSkip(t)
	var err error

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	t.Run("start-headscale", func(t *testing.T) {
		err = scenario.StartHeadscale()
		if err != nil {
			t.Errorf("failed to create start headcale: %s", err)
		}

		err = scenario.Headscale().WaitForReady()
		if err != nil {
			t.Errorf("headscale failed to become ready: %s", err)
		}

	})

	t.Run("create-namespace", func(t *testing.T) {
		err := scenario.CreateNamespace("test-space")
		if err != nil {
			t.Errorf("failed to create namespace: %s", err)
		}

		if _, ok := scenario.namespaces["test-space"]; !ok {
			t.Errorf("namespace is not in scenario")
		}
	})

	t.Run("create-auth-key", func(t *testing.T) {
		_, err := scenario.CreatePreAuthKey("test-space")
		if err != nil {
			t.Errorf("failed to create preauthkey: %s", err)
		}
	})

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestCreateTailscale(t *testing.T) {
	IntegrationSkip(t)

	var scenario *Scenario
	var err error

	namespace := "only-create-containers"

	scenario, err = NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario.namespaces[namespace] = &Namespace{
		Clients: make(map[string]*tsic.TailscaleInContainer),
	}

	t.Run("create-tailscale", func(t *testing.T) {
		err := scenario.CreateTailscaleNodesInNamespace(namespace, "1.32.0", 3)
		if err != nil {
			t.Errorf("failed to add tailscale nodes: %s", err)
		}

		if clients := len(scenario.namespaces[namespace].Clients); clients != 3 {
			t.Errorf("wrong number of tailscale clients: %d != %d", clients, 3)
		}
	})

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestTailscaleNodesJoiningHeadcale(t *testing.T) {
	IntegrationSkip(t)

	var err error

	namespace := "join-node-test"

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	t.Run("start-headscale", func(t *testing.T) {
		err = scenario.StartHeadscale()
		if err != nil {
			t.Errorf("failed to create start headcale: %s", err)
		}

		headscale := scenario.Headscale()
		err = headscale.WaitForReady()
		if err != nil {
			t.Errorf("headscale failed to become ready: %s", err)
		}

	})

	t.Run("create-namespace", func(t *testing.T) {
		err := scenario.CreateNamespace(namespace)
		if err != nil {
			t.Errorf("failed to create namespace: %s", err)
		}

		if _, ok := scenario.namespaces[namespace]; !ok {
			t.Errorf("namespace is not in scenario")
		}
	})

	t.Run("create-tailscale", func(t *testing.T) {
		err := scenario.CreateTailscaleNodesInNamespace(namespace, "1.32.0", 2)
		if err != nil {
			t.Errorf("failed to add tailscale nodes: %s", err)
		}

		if clients := len(scenario.namespaces[namespace].Clients); clients != 2 {
			t.Errorf("wrong number of tailscale clients: %d != %d", clients, 2)
		}
	})

	t.Run("join-headscale", func(t *testing.T) {
		key, err := scenario.CreatePreAuthKey(namespace)
		if err != nil {
			t.Errorf("failed to create preauthkey: %s", err)
		}

		err = scenario.RunTailscaleUp(namespace, scenario.Headscale().GetEndpoint(), key.GetKey())
		if err != nil {
			t.Errorf("failed to login: %s", err)
		}

	})

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}
