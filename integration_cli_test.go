//go:build integration
// +build integration

package headscale

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type IntegrationCLITestSuite struct {
	suite.Suite
	stats *suite.SuiteInformation

	pool      dockertest.Pool
	network   dockertest.Network
	headscale dockertest.Resource
	env       []string
}

func TestCLIIntegrationTestSuite(t *testing.T) {
	s := new(IntegrationCLITestSuite)

	suite.Run(t, s)
}

func (s *IntegrationCLITestSuite) SetupTest() {
	var err error

	if ppool, err := dockertest.NewPool(""); err == nil {
		s.pool = *ppool
	} else {
		s.FailNow(fmt.Sprintf("Could not connect to docker: %s", err), "")
	}

	if pnetwork, err := s.pool.CreateNetwork("headscale-test"); err == nil {
		s.network = *pnetwork
	} else {
		s.FailNow(fmt.Sprintf("Could not create network: %s", err), "")
	}

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile",
		ContextDir: ".",
	}

	currentPath, err := os.Getwd()
	if err != nil {
		s.FailNow(fmt.Sprintf("Could not determine current path: %s", err), "")
	}

	headscaleOptions := &dockertest.RunOptions{
		Name: "headscale-cli",
		Mounts: []string{
			fmt.Sprintf("%s/integration_test/etc:/etc/headscale", currentPath),
		},
		Networks: []*dockertest.Network{&s.network},
		Cmd:      []string{"headscale", "serve"},
	}

	err = s.pool.RemoveContainerByName(headscaleHostname)
	if err != nil {
		s.FailNow(fmt.Sprintf("Could not remove existing container before building test: %s", err), "")
	}

	fmt.Println("Creating headscale container")
	if pheadscale, err := s.pool.BuildAndRunWithBuildOptions(headscaleBuildOptions, headscaleOptions, DockerRestartPolicy); err == nil {
		s.headscale = *pheadscale
	} else {
		s.FailNow(fmt.Sprintf("Could not start headscale container: %s", err), "")
	}
	fmt.Println("Created headscale container")

	fmt.Println("Waiting for headscale to be ready")
	hostEndpoint := fmt.Sprintf("localhost:%s", s.headscale.GetPort("8080/tcp"))

	if err := s.pool.Retry(func() error {
		url := fmt.Sprintf("http://%s/health", hostEndpoint)
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status code not OK")
		}

		return nil
	}); err != nil {
		// TODO(kradalby): If we cannot access headscale, or any other fatal error during
		// test setup, we need to abort and tear down. However, testify does not seem to
		// support that at the moment:
		// https://github.com/stretchr/testify/issues/849
		return // fmt.Errorf("Could not connect to headscale: %s", err)
	}
	fmt.Println("headscale container is ready")
}

func (s *IntegrationCLITestSuite) TearDownTest() {
	if err := s.pool.Purge(&s.headscale); err != nil {
		log.Printf("Could not purge resource: %s\n", err)
	}

	if err := s.network.Close(); err != nil {
		log.Printf("Could not close network: %s\n", err)
	}
}

func (s *IntegrationCLITestSuite) HandleStats(
	suiteName string,
	stats *suite.SuiteInformation,
) {
	s.stats = stats
}

func (s *IntegrationCLITestSuite) createNamespace(name string) (*v1.Namespace, error) {
	result, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"namespaces",
			"create",
			name,
			"--output",
			"json",
		},
		[]string{},
	)
	if err != nil {
		return nil, err
	}

	var namespace v1.Namespace
	err = json.Unmarshal([]byte(result), &namespace)
	if err != nil {
		return nil, err
	}

	return &namespace, nil
}

func (s *IntegrationCLITestSuite) TestNamespaceCommand() {
	names := []string{"namespace1", "otherspace", "tasty"}
	namespaces := make([]*v1.Namespace, len(names))

	for index, namespaceName := range names {
		namespace, err := s.createNamespace(namespaceName)
		assert.Nil(s.T(), err)

		namespaces[index] = namespace
	}

	assert.Len(s.T(), namespaces, len(names))

	assert.Equal(s.T(), names[0], namespaces[0].Name)
	assert.Equal(s.T(), names[1], namespaces[1].Name)
	assert.Equal(s.T(), names[2], namespaces[2].Name)

	// Test list namespaces
	listResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"namespaces",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedNamespaces []v1.Namespace
	err = json.Unmarshal([]byte(listResult), &listedNamespaces)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), names[0], listedNamespaces[0].Name)
	assert.Equal(s.T(), names[1], listedNamespaces[1].Name)
	assert.Equal(s.T(), names[2], listedNamespaces[2].Name)

	// Test rename namespace
	renameResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"namespaces",
			"rename",
			"--output",
			"json",
			"tasty",
			"newname",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var renamedNamespace v1.Namespace
	err = json.Unmarshal([]byte(renameResult), &renamedNamespace)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), renamedNamespace.Name, "newname")

	// Test list after rename namespaces
	listAfterRenameResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"namespaces",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedAfterRenameNamespaces []v1.Namespace
	err = json.Unmarshal([]byte(listAfterRenameResult), &listedAfterRenameNamespaces)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), names[0], listedAfterRenameNamespaces[0].Name)
	assert.Equal(s.T(), names[1], listedAfterRenameNamespaces[1].Name)
	assert.Equal(s.T(), "newname", listedAfterRenameNamespaces[2].Name)
}

func (s *IntegrationCLITestSuite) TestPreAuthKeyCommand() {
	count := 5

	namespace, err := s.createNamespace("pre-auth-key-namespace")

	keys := make([]*v1.PreAuthKey, count)
	assert.Nil(s.T(), err)

	for i := 0; i < count; i++ {
		preAuthResult, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--namespace",
				namespace.Name,
				"create",
				"--reusable",
				"--expiration",
				"24h",
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var preAuthKey v1.PreAuthKey
		err = json.Unmarshal([]byte(preAuthResult), &preAuthKey)
		assert.Nil(s.T(), err)

		keys[i] = &preAuthKey
	}

	assert.Len(s.T(), keys, 5)

	// Test list of keys
	listResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedPreAuthKeys []v1.PreAuthKey
	err = json.Unmarshal([]byte(listResult), &listedPreAuthKeys)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), "1", listedPreAuthKeys[0].Id)
	assert.Equal(s.T(), "2", listedPreAuthKeys[1].Id)
	assert.Equal(s.T(), "3", listedPreAuthKeys[2].Id)
	assert.Equal(s.T(), "4", listedPreAuthKeys[3].Id)
	assert.Equal(s.T(), "5", listedPreAuthKeys[4].Id)

	assert.NotEmpty(s.T(), listedPreAuthKeys[0].Key)
	assert.NotEmpty(s.T(), listedPreAuthKeys[1].Key)
	assert.NotEmpty(s.T(), listedPreAuthKeys[2].Key)
	assert.NotEmpty(s.T(), listedPreAuthKeys[3].Key)
	assert.NotEmpty(s.T(), listedPreAuthKeys[4].Key)

	assert.True(s.T(), listedPreAuthKeys[0].Expiration.AsTime().After(time.Now()))
	assert.True(s.T(), listedPreAuthKeys[1].Expiration.AsTime().After(time.Now()))
	assert.True(s.T(), listedPreAuthKeys[2].Expiration.AsTime().After(time.Now()))
	assert.True(s.T(), listedPreAuthKeys[3].Expiration.AsTime().After(time.Now()))
	assert.True(s.T(), listedPreAuthKeys[4].Expiration.AsTime().After(time.Now()))

	assert.True(
		s.T(),
		listedPreAuthKeys[0].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		listedPreAuthKeys[1].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		listedPreAuthKeys[2].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		listedPreAuthKeys[3].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		listedPreAuthKeys[4].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)

	// Expire three keys
	for i := 0; i < 3; i++ {
		_, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--namespace",
				namespace.Name,
				"expire",
				listedPreAuthKeys[i].Key,
			},
			[]string{},
		)
		assert.Nil(s.T(), err)
	}

	// Test list pre auth keys after expire
	listAfterExpireResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedAfterExpirePreAuthKeys []v1.PreAuthKey
	err = json.Unmarshal([]byte(listAfterExpireResult), &listedAfterExpirePreAuthKeys)
	assert.Nil(s.T(), err)

	assert.True(
		s.T(),
		listedAfterExpirePreAuthKeys[0].Expiration.AsTime().Before(time.Now()),
	)
	assert.True(
		s.T(),
		listedAfterExpirePreAuthKeys[1].Expiration.AsTime().Before(time.Now()),
	)
	assert.True(
		s.T(),
		listedAfterExpirePreAuthKeys[2].Expiration.AsTime().Before(time.Now()),
	)
	assert.True(
		s.T(),
		listedAfterExpirePreAuthKeys[3].Expiration.AsTime().After(time.Now()),
	)
	assert.True(
		s.T(),
		listedAfterExpirePreAuthKeys[4].Expiration.AsTime().After(time.Now()),
	)
}

func (s *IntegrationCLITestSuite) TestPreAuthKeyCommandWithoutExpiry() {
	namespace, err := s.createNamespace("pre-auth-key-without-exp-namespace")
	assert.Nil(s.T(), err)

	preAuthResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"create",
			"--reusable",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var preAuthKey v1.PreAuthKey
	err = json.Unmarshal([]byte(preAuthResult), &preAuthKey)
	assert.Nil(s.T(), err)

	// Test list of keys
	listResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedPreAuthKeys []v1.PreAuthKey
	err = json.Unmarshal([]byte(listResult), &listedPreAuthKeys)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listedPreAuthKeys, 1)

	assert.True(s.T(), listedPreAuthKeys[0].Expiration.AsTime().After(time.Now()))
	assert.True(
		s.T(),
		listedPreAuthKeys[0].Expiration.AsTime().Before(time.Now().Add(time.Minute*70)),
	)
}

func (s *IntegrationCLITestSuite) TestPreAuthKeyCommandReusableEphemeral() {
	namespace, err := s.createNamespace("pre-auth-key-reus-ephm-namespace")
	assert.Nil(s.T(), err)

	preAuthReusableResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"create",
			"--reusable=true",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var preAuthReusableKey v1.PreAuthKey
	err = json.Unmarshal([]byte(preAuthReusableResult), &preAuthReusableKey)
	assert.Nil(s.T(), err)

	assert.True(s.T(), preAuthReusableKey.GetReusable())
	assert.False(s.T(), preAuthReusableKey.GetEphemeral())

	preAuthEphemeralResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"create",
			"--ephemeral=true",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var preAuthEphemeralKey v1.PreAuthKey
	err = json.Unmarshal([]byte(preAuthEphemeralResult), &preAuthEphemeralKey)
	assert.Nil(s.T(), err)

	assert.True(s.T(), preAuthEphemeralKey.GetEphemeral())
	assert.False(s.T(), preAuthEphemeralKey.GetReusable())

	// TODO(kradalby): Evaluate if we need a case to test for reusable and ephemeral
	// preAuthReusableAndEphemeralResult, err := ExecuteCommand(
	// 	&s.headscale,
	// 	[]string{
	// 		"headscale",
	// 		"preauthkeys",
	// 		"--namespace",
	// 		namespace.Name,
	// 		"create",
	// 		"--ephemeral",
	// 		"--reusable",
	// 		"--output",
	// 		"json",
	// 	},
	// 	[]string{},
	// )
	// assert.NotNil(s.T(), err)

	// Test list of keys
	listResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedPreAuthKeys []v1.PreAuthKey
	err = json.Unmarshal([]byte(listResult), &listedPreAuthKeys)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listedPreAuthKeys, 2)
}

func (s *IntegrationCLITestSuite) TestNodeTagCommand() {
	namespace, err := s.createNamespace("machine-namespace")
	assert.Nil(s.T(), err)

	machineKeys := []string{
		"9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--namespace",
				namespace.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"--namespace",
				namespace.Name,
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var machine v1.Machine
		err = json.Unmarshal([]byte(machineResult), &machine)
		assert.Nil(s.T(), err)

		machines[index] = &machine
	}
	assert.Len(s.T(), machines, len(machineKeys))

	addTagResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"tag",
			"-i", "1",
			"-t", "tag:test",
			"--output", "json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var machine v1.Machine
	err = json.Unmarshal([]byte(addTagResult), &machine)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), []string{"tag:test"}, machine.ForcedTags)

	// try to set a wrong tag and retrieve the error
	wrongTagResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"tag",
			"-i", "2",
			"-t", "wrong-tag",
			"--output", "json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)
	type errOutput struct {
		Error string `json:"error"`
	}
	var errorOutput errOutput
	err = json.Unmarshal([]byte(wrongTagResult), &errorOutput)
	assert.Nil(s.T(), err)
	assert.Contains(s.T(), errorOutput.Error, "Invalid tag detected")

	// Test list all nodes after added seconds
	listAllResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output", "json",
		},
		[]string{},
	)
	resultMachines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)
	json.Unmarshal([]byte(listAllResult), &resultMachines)
	found := false
	for _, machine := range resultMachines {
		if machine.ForcedTags != nil {
			for _, tag := range machine.ForcedTags {
				if tag == "tag:test" {
					found = true
				}
			}
		}
	}
	assert.Equal(
		s.T(),
		true,
		found,
		"should find a machine with the tag 'tag:test' in the list of machines",
	)
}

func (s *IntegrationCLITestSuite) TestNodeCommand() {
	namespace, err := s.createNamespace("machine-namespace")
	assert.Nil(s.T(), err)

	secondNamespace, err := s.createNamespace("other-namespace")
	assert.Nil(s.T(), err)

	// Randomly generated machine keys
	machineKeys := []string{
		"9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--namespace",
				namespace.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"--namespace",
				namespace.Name,
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var machine v1.Machine
		err = json.Unmarshal([]byte(machineResult), &machine)
		assert.Nil(s.T(), err)

		machines[index] = &machine
	}

	assert.Len(s.T(), machines, len(machineKeys))

	// Test list all nodes after added seconds
	listAllResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAll []v1.Machine
	err = json.Unmarshal([]byte(listAllResult), &listAll)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAll, 5)

	assert.Equal(s.T(), uint64(1), listAll[0].Id)
	assert.Equal(s.T(), uint64(2), listAll[1].Id)
	assert.Equal(s.T(), uint64(3), listAll[2].Id)
	assert.Equal(s.T(), uint64(4), listAll[3].Id)
	assert.Equal(s.T(), uint64(5), listAll[4].Id)

	assert.Equal(s.T(), "machine-1", listAll[0].Name)
	assert.Equal(s.T(), "machine-2", listAll[1].Name)
	assert.Equal(s.T(), "machine-3", listAll[2].Name)
	assert.Equal(s.T(), "machine-4", listAll[3].Name)
	assert.Equal(s.T(), "machine-5", listAll[4].Name)

	otherNamespaceMachineKeys := []string{
		"b5b444774186d4217adcec407563a1223929465ee2c68a4da13af0d0185b4f8e",
		"dc721977ac7415aafa87f7d4574cbe07c6b171834a6d37375782bdc1fb6b3584",
	}
	otherNamespaceMachines := make([]*v1.Machine, len(otherNamespaceMachineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range otherNamespaceMachineKeys {
		_, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("otherNamespace-machine-%d", index+1),
				"--namespace",
				secondNamespace.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"--namespace",
				secondNamespace.Name,
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var machine v1.Machine
		err = json.Unmarshal([]byte(machineResult), &machine)
		assert.Nil(s.T(), err)

		otherNamespaceMachines[index] = &machine
	}

	assert.Len(s.T(), otherNamespaceMachines, len(otherNamespaceMachineKeys))

	// Test list all nodes after added otherNamespace
	listAllWithotherNamespaceResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAllWithotherNamespace []v1.Machine
	err = json.Unmarshal(
		[]byte(listAllWithotherNamespaceResult),
		&listAllWithotherNamespace,
	)
	assert.Nil(s.T(), err)

	// All nodes, machines + otherNamespace
	assert.Len(s.T(), listAllWithotherNamespace, 7)

	assert.Equal(s.T(), uint64(6), listAllWithotherNamespace[5].Id)
	assert.Equal(s.T(), uint64(7), listAllWithotherNamespace[6].Id)

	assert.Equal(s.T(), "otherNamespace-machine-1", listAllWithotherNamespace[5].Name)
	assert.Equal(s.T(), "otherNamespace-machine-2", listAllWithotherNamespace[6].Name)

	// Test list all nodes after added otherNamespace
	listOnlyotherNamespaceMachineNamespaceResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--namespace",
			secondNamespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listOnlyotherNamespaceMachineNamespace []v1.Machine
	err = json.Unmarshal(
		[]byte(listOnlyotherNamespaceMachineNamespaceResult),
		&listOnlyotherNamespaceMachineNamespace,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listOnlyotherNamespaceMachineNamespace, 2)

	assert.Equal(s.T(), uint64(6), listOnlyotherNamespaceMachineNamespace[0].Id)
	assert.Equal(s.T(), uint64(7), listOnlyotherNamespaceMachineNamespace[1].Id)

	assert.Equal(
		s.T(),
		"otherNamespace-machine-1",
		listOnlyotherNamespaceMachineNamespace[0].Name,
	)
	assert.Equal(
		s.T(),
		"otherNamespace-machine-2",
		listOnlyotherNamespaceMachineNamespace[1].Name,
	)

	// Delete a machines
	_, err = ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"delete",
			"--identifier",
			// Delete the last added machine
			"4",
			"--output",
			"json",
			"--force",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	// Test: list main namespace after machine is deleted
	listOnlyMachineNamespaceAfterDeleteResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--namespace",
			namespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listOnlyMachineNamespaceAfterDelete []v1.Machine
	err = json.Unmarshal(
		[]byte(listOnlyMachineNamespaceAfterDeleteResult),
		&listOnlyMachineNamespaceAfterDelete,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listOnlyMachineNamespaceAfterDelete, 4)
}

func (s *IntegrationCLITestSuite) TestNodeExpireCommand() {
	namespace, err := s.createNamespace("machine-expire-namespace")
	assert.Nil(s.T(), err)

	// Randomly generated machine keys
	machineKeys := []string{
		"9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--namespace",
				namespace.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"--namespace",
				namespace.Name,
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var machine v1.Machine
		err = json.Unmarshal([]byte(machineResult), &machine)
		assert.Nil(s.T(), err)

		machines[index] = &machine
	}

	assert.Len(s.T(), machines, len(machineKeys))

	listAllResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAll []v1.Machine
	err = json.Unmarshal([]byte(listAllResult), &listAll)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAll, 5)

	assert.True(s.T(), listAll[0].Expiry.AsTime().IsZero())
	assert.True(s.T(), listAll[1].Expiry.AsTime().IsZero())
	assert.True(s.T(), listAll[2].Expiry.AsTime().IsZero())
	assert.True(s.T(), listAll[3].Expiry.AsTime().IsZero())
	assert.True(s.T(), listAll[4].Expiry.AsTime().IsZero())

	for i := 0; i < 3; i++ {
		_, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"expire",
				"--identifier",
				fmt.Sprintf("%d", listAll[i].Id),
			},
			[]string{},
		)
		assert.Nil(s.T(), err)
	}

	listAllAfterExpiryResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAllAfterExpiry []v1.Machine
	err = json.Unmarshal([]byte(listAllAfterExpiryResult), &listAllAfterExpiry)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAllAfterExpiry, 5)

	assert.True(s.T(), listAllAfterExpiry[0].Expiry.AsTime().Before(time.Now()))
	assert.True(s.T(), listAllAfterExpiry[1].Expiry.AsTime().Before(time.Now()))
	assert.True(s.T(), listAllAfterExpiry[2].Expiry.AsTime().Before(time.Now()))
	assert.True(s.T(), listAllAfterExpiry[3].Expiry.AsTime().IsZero())
	assert.True(s.T(), listAllAfterExpiry[4].Expiry.AsTime().IsZero())
}

func (s *IntegrationCLITestSuite) TestNodeRenameCommand() {
	namespace, err := s.createNamespace("machine-rename-command")
	assert.Nil(s.T(), err)

	// Randomly generated machine keys
	machineKeys := []string{
		"cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		"8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--namespace",
				namespace.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"--namespace",
				namespace.Name,
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var machine v1.Machine
		err = json.Unmarshal([]byte(machineResult), &machine)
		assert.Nil(s.T(), err)

		machines[index] = &machine
	}

	assert.Len(s.T(), machines, len(machineKeys))

	listAllResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAll []v1.Machine
	err = json.Unmarshal([]byte(listAllResult), &listAll)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAll, 5)

	assert.Contains(s.T(), listAll[0].GetGivenName(), "machine-1")
	assert.Contains(s.T(), listAll[1].GetGivenName(), "machine-2")
	assert.Contains(s.T(), listAll[2].GetGivenName(), "machine-3")
	assert.Contains(s.T(), listAll[3].GetGivenName(), "machine-4")
	assert.Contains(s.T(), listAll[4].GetGivenName(), "machine-5")

	for i := 0; i < 3; i++ {
		_, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"rename",
				"--identifier",
				fmt.Sprintf("%d", listAll[i].Id),
				fmt.Sprintf("newmachine-%d", i+1),
			},
			[]string{},
		)
		assert.Nil(s.T(), err)
	}

	listAllAfterRenameResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAllAfterRename []v1.Machine
	err = json.Unmarshal([]byte(listAllAfterRenameResult), &listAllAfterRename)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAllAfterRename, 5)

	assert.Equal(s.T(), "newmachine-1", listAllAfterRename[0].GetGivenName())
	assert.Equal(s.T(), "newmachine-2", listAllAfterRename[1].GetGivenName())
	assert.Equal(s.T(), "newmachine-3", listAllAfterRename[2].GetGivenName())
	assert.Contains(s.T(), listAllAfterRename[3].GetGivenName(), "machine-4")
	assert.Contains(s.T(), listAllAfterRename[4].GetGivenName(), "machine-5")

	// Test failure for too long names
	result, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"rename",
			"--identifier",
			fmt.Sprintf("%d", listAll[4].Id),
			"testmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaachine12345678901234567890",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)
	assert.Contains(s.T(), result, "not be over 63 chars")

	listAllAfterRenameAttemptResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAllAfterRenameAttempt []v1.Machine
	err = json.Unmarshal(
		[]byte(listAllAfterRenameAttemptResult),
		&listAllAfterRenameAttempt,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAllAfterRenameAttempt, 5)

	assert.Equal(s.T(), "newmachine-1", listAllAfterRenameAttempt[0].GetGivenName())
	assert.Equal(s.T(), "newmachine-2", listAllAfterRenameAttempt[1].GetGivenName())
	assert.Equal(s.T(), "newmachine-3", listAllAfterRenameAttempt[2].GetGivenName())
	assert.Contains(s.T(), listAllAfterRenameAttempt[3].GetGivenName(), "machine-4")
	assert.Contains(s.T(), listAllAfterRenameAttempt[4].GetGivenName(), "machine-5")
}

func (s *IntegrationCLITestSuite) TestRouteCommand() {
	namespace, err := s.createNamespace("routes-namespace")
	assert.Nil(s.T(), err)

	// Randomly generated machine keys
	machineKey := "9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe"

	_, err = ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"debug",
			"create-node",
			"--name",
			"route-machine",
			"--namespace",
			namespace.Name,
			"--key",
			machineKey,
			"--route",
			"10.0.0.0/8",
			"--route",
			"192.168.1.0/24",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	machineResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"--namespace",
			namespace.Name,
			"register",
			"--key",
			machineKey,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var machine v1.Machine
	err = json.Unmarshal([]byte(machineResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), uint64(1), machine.Id)
	assert.Equal(s.T(), "route-machine", machine.Name)

	listAllResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
			"--identifier",
			"0",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAll v1.Routes
	err = json.Unmarshal([]byte(listAllResult), &listAll)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAll.AdvertisedRoutes, 2)
	assert.Contains(s.T(), listAll.AdvertisedRoutes, "10.0.0.0/8")
	assert.Contains(s.T(), listAll.AdvertisedRoutes, "192.168.1.0/24")

	assert.Empty(s.T(), listAll.EnabledRoutes)

	enableTwoRoutesResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"routes",
			"enable",
			"--output",
			"json",
			"--identifier",
			"0",
			"--route",
			"10.0.0.0/8",
			"--route",
			"192.168.1.0/24",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var enableTwoRoutes v1.Routes
	err = json.Unmarshal([]byte(enableTwoRoutesResult), &enableTwoRoutes)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), enableTwoRoutes.AdvertisedRoutes, 2)
	assert.Contains(s.T(), enableTwoRoutes.AdvertisedRoutes, "10.0.0.0/8")
	assert.Contains(s.T(), enableTwoRoutes.AdvertisedRoutes, "192.168.1.0/24")

	assert.Len(s.T(), enableTwoRoutes.EnabledRoutes, 2)
	assert.Contains(s.T(), enableTwoRoutes.EnabledRoutes, "10.0.0.0/8")
	assert.Contains(s.T(), enableTwoRoutes.EnabledRoutes, "192.168.1.0/24")

	// Enable only one route, effectively disabling one of the routes
	enableOneRouteResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"routes",
			"enable",
			"--output",
			"json",
			"--identifier",
			"0",
			"--route",
			"10.0.0.0/8",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var enableOneRoute v1.Routes
	err = json.Unmarshal([]byte(enableOneRouteResult), &enableOneRoute)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), enableOneRoute.AdvertisedRoutes, 2)
	assert.Contains(s.T(), enableOneRoute.AdvertisedRoutes, "10.0.0.0/8")
	assert.Contains(s.T(), enableOneRoute.AdvertisedRoutes, "192.168.1.0/24")

	assert.Len(s.T(), enableOneRoute.EnabledRoutes, 1)
	assert.Contains(s.T(), enableOneRoute.EnabledRoutes, "10.0.0.0/8")

	// Enable only one route, effectively disabling one of the routes
	failEnableNonAdvertisedRoute, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"routes",
			"enable",
			"--output",
			"json",
			"--identifier",
			"0",
			"--route",
			"11.0.0.0/8",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	assert.Contains(
		s.T(),
		string(failEnableNonAdvertisedRoute),
		"route (route-machine) is not available on node",
	)

	// Enable all routes on host
	enableAllRouteResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"routes",
			"enable",
			"--output",
			"json",
			"--identifier",
			"0",
			"--all",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var enableAllRoute v1.Routes
	err = json.Unmarshal([]byte(enableAllRouteResult), &enableAllRoute)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), enableAllRoute.AdvertisedRoutes, 2)
	assert.Contains(s.T(), enableAllRoute.AdvertisedRoutes, "10.0.0.0/8")
	assert.Contains(s.T(), enableAllRoute.AdvertisedRoutes, "192.168.1.0/24")

	assert.Len(s.T(), enableAllRoute.EnabledRoutes, 2)
	assert.Contains(s.T(), enableAllRoute.EnabledRoutes, "10.0.0.0/8")
	assert.Contains(s.T(), enableAllRoute.EnabledRoutes, "192.168.1.0/24")
}

func (s *IntegrationCLITestSuite) TestApiKeyCommand() {
	count := 5

	keys := make([]string, count)

	for i := 0; i < count; i++ {
		apiResult, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"apikeys",
				"create",
				"--expiration",
				"24h",
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)
		assert.NotEmpty(s.T(), apiResult)

		// var apiKey v1.ApiKey
		// err = json.Unmarshal([]byte(apiResult), &apiKey)
		// assert.Nil(s.T(), err)

		keys[i] = apiResult
	}

	assert.Len(s.T(), keys, 5)

	// Test list of keys
	listResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"apikeys",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedApiKeys []v1.ApiKey
	err = json.Unmarshal([]byte(listResult), &listedApiKeys)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listedApiKeys, 5)

	assert.Equal(s.T(), uint64(1), listedApiKeys[0].Id)
	assert.Equal(s.T(), uint64(2), listedApiKeys[1].Id)
	assert.Equal(s.T(), uint64(3), listedApiKeys[2].Id)
	assert.Equal(s.T(), uint64(4), listedApiKeys[3].Id)
	assert.Equal(s.T(), uint64(5), listedApiKeys[4].Id)

	assert.NotEmpty(s.T(), listedApiKeys[0].Prefix)
	assert.NotEmpty(s.T(), listedApiKeys[1].Prefix)
	assert.NotEmpty(s.T(), listedApiKeys[2].Prefix)
	assert.NotEmpty(s.T(), listedApiKeys[3].Prefix)
	assert.NotEmpty(s.T(), listedApiKeys[4].Prefix)

	assert.True(s.T(), listedApiKeys[0].Expiration.AsTime().After(time.Now()))
	assert.True(s.T(), listedApiKeys[1].Expiration.AsTime().After(time.Now()))
	assert.True(s.T(), listedApiKeys[2].Expiration.AsTime().After(time.Now()))
	assert.True(s.T(), listedApiKeys[3].Expiration.AsTime().After(time.Now()))
	assert.True(s.T(), listedApiKeys[4].Expiration.AsTime().After(time.Now()))

	assert.True(
		s.T(),
		listedApiKeys[0].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		listedApiKeys[1].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		listedApiKeys[2].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		listedApiKeys[3].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		listedApiKeys[4].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)

	expiredPrefixes := make(map[string]bool)

	// Expire three keys
	for i := 0; i < 3; i++ {
		_, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"apikeys",
				"expire",
				"--prefix",
				listedApiKeys[i].Prefix,
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		expiredPrefixes[listedApiKeys[i].Prefix] = true
	}

	// Test list pre auth keys after expire
	listAfterExpireResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"apikeys",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedAfterExpireApiKeys []v1.ApiKey
	err = json.Unmarshal([]byte(listAfterExpireResult), &listedAfterExpireApiKeys)
	assert.Nil(s.T(), err)

	for index := range listedAfterExpireApiKeys {
		if _, ok := expiredPrefixes[listedAfterExpireApiKeys[index].Prefix]; ok {
			// Expired
			assert.True(
				s.T(),
				listedAfterExpireApiKeys[index].Expiration.AsTime().Before(time.Now()),
			)
		} else {
			// Not expired
			assert.False(
				s.T(),
				listedAfterExpireApiKeys[index].Expiration.AsTime().Before(time.Now()),
			)
		}
	}
}

func (s *IntegrationCLITestSuite) TestNodeMoveCommand() {
	oldNamespace, err := s.createNamespace("old-namespace")
	assert.Nil(s.T(), err)
	newNamespace, err := s.createNamespace("new-namespace")
	assert.Nil(s.T(), err)

	// Randomly generated machine key
	machineKey := "688411b767663479632d44140f08a9fde87383adc7cdeb518f62ce28a17ef0aa"

	_, err = ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"debug",
			"create-node",
			"--name",
			"nomad-machine",
			"--namespace",
			oldNamespace.Name,
			"--key",
			machineKey,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	machineResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"--namespace",
			oldNamespace.Name,
			"register",
			"--key",
			machineKey,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var machine v1.Machine
	err = json.Unmarshal([]byte(machineResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), uint64(1), machine.Id)
	assert.Equal(s.T(), "nomad-machine", machine.Name)
	assert.Equal(s.T(), machine.Namespace.Name, oldNamespace.Name)

	machineId := fmt.Sprintf("%d", machine.Id)

	moveToNewNSResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--namespace",
			newNamespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	err = json.Unmarshal([]byte(moveToNewNSResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), machine.Namespace, newNamespace)

	listAllNodesResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var allNodes []v1.Machine
	err = json.Unmarshal([]byte(listAllNodesResult), &allNodes)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), allNodes, 1)

	assert.Equal(s.T(), allNodes[0].Id, machine.Id)
	assert.Equal(s.T(), allNodes[0].Namespace, machine.Namespace)
	assert.Equal(s.T(), allNodes[0].Namespace, newNamespace)

	moveToNonExistingNSResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--namespace",
			"non-existing-namespace",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	assert.Contains(
		s.T(),
		string(moveToNonExistingNSResult),
		"Namespace not found",
	)
	assert.Equal(s.T(), machine.Namespace, newNamespace)

	moveToOldNSResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--namespace",
			oldNamespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	err = json.Unmarshal([]byte(moveToOldNSResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), machine.Namespace, oldNamespace)

	moveToSameNSResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--namespace",
			oldNamespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	err = json.Unmarshal([]byte(moveToSameNSResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), machine.Namespace, oldNamespace)
}

func (s *IntegrationCLITestSuite) TestLoadConfigFromCommand() {
	// TODO: make sure defaultConfig is not same as altConfig
	defaultConfig, err := os.ReadFile("integration_test/etc/config.dump.gold.yaml")
	assert.Nil(s.T(), err)
	altConfig, err := os.ReadFile("integration_test/etc/alt-config.dump.gold.yaml")
	assert.Nil(s.T(), err)

	_, err = ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"dumpConfig",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	defaultDumpConfig, err := os.ReadFile("integration_test/etc/config.dump.yaml")
	assert.Nil(s.T(), err)

	assert.YAMLEq(s.T(), string(defaultConfig), string(defaultDumpConfig))

	_, err = ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"-c",
			"/etc/headscale/alt-config.yaml",
			"dumpConfig",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	altDumpConfig, err := os.ReadFile("integration_test/etc/config.dump.yaml")
	assert.Nil(s.T(), err)

	assert.YAMLEq(s.T(), string(altConfig), string(altDumpConfig))
}
