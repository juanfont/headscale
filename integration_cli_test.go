// nolint
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
	"github.com/ory/dockertest/v3/docker"
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

func TestIntegrationCLITestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests due to short flag")
	}

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

	network, err := GetFirstOrCreateNetwork(&s.pool, headscaleNetwork)
	if err != nil {
		s.FailNow(fmt.Sprintf("Failed to create or get network: %s", err), "")
	}
	s.network = network

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
		Cmd:          []string{"headscale", "serve"},
		Networks:     []*dockertest.Network{&s.network},
		ExposedPorts: []string{"8080/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8080/tcp": {{HostPort: "8080"}},
		},
	}

	err = s.pool.RemoveContainerByName(headscaleHostname)
	if err != nil {
		s.FailNow(
			fmt.Sprintf(
				"Could not remove existing container before building test: %s",
				err,
			),
			"",
		)
	}

	fmt.Println("Creating headscale container for CLI tests")
	if pheadscale, err := s.pool.BuildAndRunWithBuildOptions(headscaleBuildOptions, headscaleOptions, DockerRestartPolicy); err == nil {
		s.headscale = *pheadscale
	} else {
		s.FailNow(fmt.Sprintf("Could not start headscale container: %s", err), "")
	}
	fmt.Println("Created headscale container for CLI tests")

	fmt.Println("Waiting for headscale to be ready for CLI tests")
	hostEndpoint := fmt.Sprintf("%s:%s",
		s.headscale.GetIPInNetwork(&s.network),
		s.headscale.GetPort("8080/tcp"))

	if err := s.pool.Retry(func() error {
		url := fmt.Sprintf("http://%s/health", hostEndpoint)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("headscale for CLI test is not ready: %s\n", err)
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
	fmt.Println("headscale container is ready for CLI tests")
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

func (s *IntegrationCLITestSuite) createUser(name string) (*v1.User, error) {
	result, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"users",
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

	var user v1.User
	err = json.Unmarshal([]byte(result), &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *IntegrationCLITestSuite) TestUserCommand() {
	names := []string{"user1", "otherspace", "tasty"}
	users := make([]*v1.User, len(names))

	for index, userName := range names {
		user, err := s.createUser(userName)
		assert.Nil(s.T(), err)

		users[index] = user
	}

	assert.Len(s.T(), users, len(names))

	assert.Equal(s.T(), names[0], users[0].Name)
	assert.Equal(s.T(), names[1], users[1].Name)
	assert.Equal(s.T(), names[2], users[2].Name)

	// Test list users
	listResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"users",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedUsers []v1.User
	err = json.Unmarshal([]byte(listResult), &listedUsers)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), names[0], listedUsers[0].Name)
	assert.Equal(s.T(), names[1], listedUsers[1].Name)
	assert.Equal(s.T(), names[2], listedUsers[2].Name)

	// Test rename user
	renameResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"users",
			"rename",
			"--output",
			"json",
			"tasty",
			"newname",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var renamedUser v1.User
	err = json.Unmarshal([]byte(renameResult), &renamedUser)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), renamedUser.Name, "newname")

	// Test list after rename users
	listAfterRenameResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"users",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedAfterRenameUsers []v1.User
	err = json.Unmarshal([]byte(listAfterRenameResult), &listedAfterRenameUsers)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), names[0], listedAfterRenameUsers[0].Name)
	assert.Equal(s.T(), names[1], listedAfterRenameUsers[1].Name)
	assert.Equal(s.T(), "newname", listedAfterRenameUsers[2].Name)
}

func (s *IntegrationCLITestSuite) TestPreAuthKeyCommand() {
	count := 5

	user, err := s.createUser("pre-auth-key-user")

	keys := make([]*v1.PreAuthKey, count)
	assert.Nil(s.T(), err)

	for i := 0; i < count; i++ {
		preAuthResult, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				user.Name,
				"create",
				"--reusable",
				"--expiration",
				"24h",
				"--output",
				"json",
				"--tags",
				"tag:test1,tag:test2",
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
	listResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user.Name,
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

	// Test that tags are present
	for i := 0; i < count; i++ {
		assert.Equal(s.T(), listedPreAuthKeys[i].AclTags, []string{"tag:test1", "tag:test2"})
	}

	// Expire three keys
	for i := 0; i < 3; i++ {
		_, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				user.Name,
				"expire",
				listedPreAuthKeys[i].Key,
			},
			[]string{},
		)
		assert.Nil(s.T(), err)
	}

	// Test list pre auth keys after expire
	listAfterExpireResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user.Name,
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
	user, err := s.createUser("pre-auth-key-without-exp-user")
	assert.Nil(s.T(), err)

	preAuthResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user.Name,
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
	listResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user.Name,
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
	user, err := s.createUser("pre-auth-key-reus-ephm-user")
	assert.Nil(s.T(), err)

	preAuthReusableResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user.Name,
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

	preAuthEphemeralResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user.Name,
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
	// 		"--user",
	// 		user.Name,
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
	listResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user.Name,
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
	user, err := s.createUser("machine-user")
	assert.Nil(s.T(), err)

	machineKeys := []string{
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--user",
				user.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"--user",
				user.Name,
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

	addTagResult, _, err := ExecuteCommand(
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
	wrongTagResult, _, err := ExecuteCommand(
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
	assert.Contains(s.T(), errorOutput.Error, "tag must start with the string 'tag:'")

	// Test list all nodes after added seconds
	listAllResult, _, err := ExecuteCommand(
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
	user, err := s.createUser("machine-user")
	assert.Nil(s.T(), err)

	secondUser, err := s.createUser("other-user")
	assert.Nil(s.T(), err)

	// Randomly generated machine keys
	machineKeys := []string{
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"nodekey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"nodekey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"nodekey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--user",
				user.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"--user",
				user.Name,
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
	listAllResult, _, err := ExecuteCommand(
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

	otherUserMachineKeys := []string{
		"nodekey:b5b444774186d4217adcec407563a1223929465ee2c68a4da13af0d0185b4f8e",
		"nodekey:dc721977ac7415aafa87f7d4574cbe07c6b171834a6d37375782bdc1fb6b3584",
	}
	otherUserMachines := make([]*v1.Machine, len(otherUserMachineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range otherUserMachineKeys {
		_, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("otherUser-machine-%d", index+1),
				"--user",
				secondUser.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"--user",
				secondUser.Name,
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

		otherUserMachines[index] = &machine
	}

	assert.Len(s.T(), otherUserMachines, len(otherUserMachineKeys))

	// Test list all nodes after added otherUser
	listAllWithotherUserResult, _, err := ExecuteCommand(
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

	var listAllWithotherUser []v1.Machine
	err = json.Unmarshal(
		[]byte(listAllWithotherUserResult),
		&listAllWithotherUser,
	)
	assert.Nil(s.T(), err)

	// All nodes, machines + otherUser
	assert.Len(s.T(), listAllWithotherUser, 7)

	assert.Equal(s.T(), uint64(6), listAllWithotherUser[5].Id)
	assert.Equal(s.T(), uint64(7), listAllWithotherUser[6].Id)

	assert.Equal(s.T(), "otherUser-machine-1", listAllWithotherUser[5].Name)
	assert.Equal(s.T(), "otherUser-machine-2", listAllWithotherUser[6].Name)

	// Test list all nodes after added otherUser
	listOnlyotherUserMachineUserResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--user",
			secondUser.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listOnlyotherUserMachineUser []v1.Machine
	err = json.Unmarshal(
		[]byte(listOnlyotherUserMachineUserResult),
		&listOnlyotherUserMachineUser,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listOnlyotherUserMachineUser, 2)

	assert.Equal(s.T(), uint64(6), listOnlyotherUserMachineUser[0].Id)
	assert.Equal(s.T(), uint64(7), listOnlyotherUserMachineUser[1].Id)

	assert.Equal(
		s.T(),
		"otherUser-machine-1",
		listOnlyotherUserMachineUser[0].Name,
	)
	assert.Equal(
		s.T(),
		"otherUser-machine-2",
		listOnlyotherUserMachineUser[1].Name,
	)

	// Delete a machines
	_, _, err = ExecuteCommand(
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

	// Test: list main user after machine is deleted
	listOnlyMachineUserAfterDeleteResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--user",
			user.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listOnlyMachineUserAfterDelete []v1.Machine
	err = json.Unmarshal(
		[]byte(listOnlyMachineUserAfterDeleteResult),
		&listOnlyMachineUserAfterDelete,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listOnlyMachineUserAfterDelete, 4)
}

func (s *IntegrationCLITestSuite) TestNodeExpireCommand() {
	user, err := s.createUser("machine-expire-user")
	assert.Nil(s.T(), err)

	// Randomly generated machine keys
	machineKeys := []string{
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"nodekey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"nodekey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"nodekey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--user",
				user.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"--user",
				user.Name,
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

	listAllResult, _, err := ExecuteCommand(
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
		_, _, err := ExecuteCommand(
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

	listAllAfterExpiryResult, _, err := ExecuteCommand(
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
	user, err := s.createUser("machine-rename-command")
	assert.Nil(s.T(), err)

	// Randomly generated machine keys
	machineKeys := []string{
		"nodekey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		"nodekey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"nodekey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--user",
				user.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, _, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"--user",
				user.Name,
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

	listAllResult, _, err := ExecuteCommand(
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
		_, _, err := ExecuteCommand(
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

	listAllAfterRenameResult, _, err := ExecuteCommand(
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
	result, _, err := ExecuteCommand(
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

	listAllAfterRenameAttemptResult, _, err := ExecuteCommand(
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

func (s *IntegrationCLITestSuite) TestApiKeyCommand() {
	count := 5

	keys := make([]string, count)

	for i := 0; i < count; i++ {
		apiResult, _, err := ExecuteCommand(
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
	listResult, _, err := ExecuteCommand(
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
		_, _, err := ExecuteCommand(
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
	listAfterExpireResult, _, err := ExecuteCommand(
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
	oldUser, err := s.createUser("old-user")
	assert.Nil(s.T(), err)
	newUser, err := s.createUser("new-user")
	assert.Nil(s.T(), err)

	// Randomly generated machine key
	machineKey := "nodekey:688411b767663479632d44140f08a9fde87383adc7cdeb518f62ce28a17ef0aa"

	_, _, err = ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"debug",
			"create-node",
			"--name",
			"nomad-machine",
			"--user",
			oldUser.Name,
			"--key",
			machineKey,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	machineResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"--user",
			oldUser.Name,
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
	assert.Equal(s.T(), machine.User.Name, oldUser.Name)

	machineId := fmt.Sprintf("%d", machine.Id)

	moveToNewNSResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--user",
			newUser.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	err = json.Unmarshal([]byte(moveToNewNSResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), machine.User, newUser)

	listAllNodesResult, _, err := ExecuteCommand(
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
	assert.Equal(s.T(), allNodes[0].User, machine.User)
	assert.Equal(s.T(), allNodes[0].User, newUser)

	moveToNonExistingNSResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--user",
			"non-existing-user",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	assert.Contains(
		s.T(),
		string(moveToNonExistingNSResult),
		"User not found",
	)
	assert.Equal(s.T(), machine.User, newUser)

	moveToOldNSResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--user",
			oldUser.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	err = json.Unmarshal([]byte(moveToOldNSResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), machine.User, oldUser)

	moveToSameNSResult, _, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--user",
			oldUser.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	err = json.Unmarshal([]byte(moveToSameNSResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), machine.User, oldUser)
}

func (s *IntegrationCLITestSuite) TestLoadConfigFromCommand() {
	// TODO: make sure defaultConfig is not same as altConfig
	defaultConfig, err := os.ReadFile("integration_test/etc/config.dump.gold.yaml")
	assert.Nil(s.T(), err)
	altConfig, err := os.ReadFile("integration_test/etc/alt-config.dump.gold.yaml")
	assert.Nil(s.T(), err)
	altEnvConfig, err := os.ReadFile("integration_test/etc/alt-env-config.dump.gold.yaml")
	assert.Nil(s.T(), err)

	_, _, err = ExecuteCommand(
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

	_, _, err = ExecuteCommand(
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

	_, _, err = ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"dumpConfig",
		},
		[]string{
			"HEADSCALE_CONFIG=/etc/headscale/alt-env-config.yaml",
		},
	)
	assert.Nil(s.T(), err)

	altEnvDumpConfig, err := os.ReadFile("integration_test/etc/config.dump.yaml")
	assert.Nil(s.T(), err)

	assert.YAMLEq(s.T(), string(altEnvConfig), string(altEnvDumpConfig))

	_, _, err = ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"-c",
			"/etc/headscale/alt-config.yaml",
			"dumpConfig",
		},
		[]string{
			"HEADSCALE_CONFIG=/etc/headscale/alt-env-config.yaml",
		},
	)
	assert.Nil(s.T(), err)

	altDumpConfig, err = os.ReadFile("integration_test/etc/config.dump.yaml")
	assert.Nil(s.T(), err)

	assert.YAMLEq(s.T(), string(altConfig), string(altDumpConfig))
}
