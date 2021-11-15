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
		log.Fatalf("Could not connect to docker: %s", err)
	}

	if pnetwork, err := s.pool.CreateNetwork("headscale-test"); err == nil {
		s.network = *pnetwork
	} else {
		log.Fatalf("Could not create network: %s", err)
	}

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile",
		ContextDir: ".",
	}

	currentPath, err := os.Getwd()
	if err != nil {
		log.Fatalf("Could not determine current path: %s", err)
	}

	headscaleOptions := &dockertest.RunOptions{
		Name: "headscale",
		Mounts: []string{
			fmt.Sprintf("%s/integration_test/etc:/etc/headscale", currentPath),
		},
		Networks: []*dockertest.Network{&s.network},
		Cmd:      []string{"headscale", "serve"},
	}

	fmt.Println("Creating headscale container")
	if pheadscale, err := s.pool.BuildAndRunWithBuildOptions(headscaleBuildOptions, headscaleOptions, DockerRestartPolicy); err == nil {
		s.headscale = *pheadscale
	} else {
		log.Fatalf("Could not start resource: %s", err)
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
	assert.True(s.T(), time.Time{}.Equal(listedPreAuthKeys[0].Expiration.AsTime()))
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

func (s *IntegrationCLITestSuite) TestNodeCommand() {
	namespace, err := s.createNamespace("machine-namespace")
	assert.Nil(s.T(), err)

	sharedNamespace, err := s.createNamespace("shared-namespace")
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

	// Test list all nodes after added shared
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

	assert.True(s.T(), listAll[0].Registered)
	assert.True(s.T(), listAll[1].Registered)
	assert.True(s.T(), listAll[2].Registered)
	assert.True(s.T(), listAll[3].Registered)
	assert.True(s.T(), listAll[4].Registered)

	sharedMachineKeys := []string{
		"b5b444774186d4217adcec407563a1223929465ee2c68a4da13af0d0185b4f8e",
		"dc721977ac7415aafa87f7d4574cbe07c6b171834a6d37375782bdc1fb6b3584",
	}
	sharedMachines := make([]*v1.Machine, len(sharedMachineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range sharedMachineKeys {
		_, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("shared-machine-%d", index+1),
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
				sharedNamespace.Name,
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

		sharedMachines[index] = &machine
	}

	assert.Len(s.T(), sharedMachines, len(sharedMachineKeys))

	// Test list all nodes after added shared
	listAllWithSharedResult, err := ExecuteCommand(
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

	var listAllWithShared []v1.Machine
	err = json.Unmarshal([]byte(listAllWithSharedResult), &listAllWithShared)
	assert.Nil(s.T(), err)

	// All nodes, machines + shared
	assert.Len(s.T(), listAllWithShared, 7)

	assert.Equal(s.T(), uint64(6), listAllWithShared[5].Id)
	assert.Equal(s.T(), uint64(7), listAllWithShared[6].Id)

	assert.Equal(s.T(), "shared-machine-1", listAllWithShared[5].Name)
	assert.Equal(s.T(), "shared-machine-2", listAllWithShared[6].Name)

	assert.True(s.T(), listAllWithShared[5].Registered)
	assert.True(s.T(), listAllWithShared[6].Registered)

	// Test list all nodes after added shared
	listOnlySharedMachineNamespaceResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--namespace",
			sharedNamespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listOnlySharedMachineNamespace []v1.Machine
	err = json.Unmarshal(
		[]byte(listOnlySharedMachineNamespaceResult),
		&listOnlySharedMachineNamespace,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listOnlySharedMachineNamespace, 2)

	assert.Equal(s.T(), uint64(6), listOnlySharedMachineNamespace[0].Id)
	assert.Equal(s.T(), uint64(7), listOnlySharedMachineNamespace[1].Id)

	assert.Equal(s.T(), "shared-machine-1", listOnlySharedMachineNamespace[0].Name)
	assert.Equal(s.T(), "shared-machine-2", listOnlySharedMachineNamespace[1].Name)

	assert.True(s.T(), listOnlySharedMachineNamespace[0].Registered)
	assert.True(s.T(), listOnlySharedMachineNamespace[1].Registered)

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

	// test: share node

	shareMachineResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"share",
			"--namespace",
			namespace.Name,
			"--identifier",
			"7",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var shareMachine v1.Machine
	err = json.Unmarshal([]byte(shareMachineResult), &shareMachine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), uint64(7), shareMachine.Id)

	assert.Equal(s.T(), "shared-machine-2", shareMachine.Name)

	assert.True(s.T(), shareMachine.Registered)

	// Test: list main namespace after machine has been shared
	listOnlyMachineNamespaceAfterShareResult, err := ExecuteCommand(
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

	var listOnlyMachineNamespaceAfterShare []v1.Machine
	err = json.Unmarshal(
		[]byte(listOnlyMachineNamespaceAfterShareResult),
		&listOnlyMachineNamespaceAfterShare,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listOnlyMachineNamespaceAfterShare, 5)

	assert.Equal(s.T(), uint64(7), listOnlyMachineNamespaceAfterShare[4].Id)

	assert.Equal(s.T(), "shared-machine-2", listOnlyMachineNamespaceAfterShare[4].Name)

	assert.True(s.T(), listOnlyMachineNamespaceAfterShare[4].Registered)

	// test: unshare node

	unshareMachineResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"unshare",
			"--namespace",
			namespace.Name,
			"--identifier",
			"7",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var unshareMachine v1.Machine
	err = json.Unmarshal([]byte(unshareMachineResult), &unshareMachine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), uint64(7), unshareMachine.Id)

	assert.Equal(s.T(), "shared-machine-2", unshareMachine.Name)

	assert.True(s.T(), unshareMachine.Registered)

	// Test: list main namespace after machine has been shared
	listOnlyMachineNamespaceAfterUnshareResult, err := ExecuteCommand(
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

	var listOnlyMachineNamespaceAfterUnshare []v1.Machine
	err = json.Unmarshal(
		[]byte(listOnlyMachineNamespaceAfterUnshareResult),
		&listOnlyMachineNamespaceAfterUnshare,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listOnlyMachineNamespaceAfterUnshare, 4)
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
	assert.True(s.T(), machine.Registered)

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
}
