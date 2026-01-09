package integration

import (
	"net/netip"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/ory/dockertest/v3"
	"tailscale.com/tailcfg"
)

type ControlServer interface {
	Shutdown() (string, string, error)
	SaveLog(string) (string, string, error)
	SaveProfile(string) error
	Execute(command []string) (string, error)
	WriteFile(path string, content []byte) error
	ConnectToNetwork(network *dockertest.Network) error
	GetHealthEndpoint() string
	GetEndpoint() string
	WaitForRunning() error
	CreateUser(user string) (*v1.User, error)
	CreateAuthKey(user uint64, reusable bool, ephemeral bool) (*v1.PreAuthKey, error)
	CreateAuthKeyWithTags(user uint64, reusable bool, ephemeral bool, tags []string) (*v1.PreAuthKey, error)
	CreateAuthKeyWithOptions(opts hsic.AuthKeyOptions) (*v1.PreAuthKey, error)
	DeleteAuthKey(id uint64) error
	ListNodes(users ...string) ([]*v1.Node, error)
	DeleteNode(nodeID uint64) error
	NodesByUser() (map[string][]*v1.Node, error)
	NodesByName() (map[string]*v1.Node, error)
	ListUsers() ([]*v1.User, error)
	MapUsers() (map[string]*v1.User, error)
	DeleteUser(userID uint64) error
	ApproveRoutes(uint64, []netip.Prefix) (*v1.Node, error)
	SetNodeTags(nodeID uint64, tags []string) error
	GetCert() []byte
	GetHostname() string
	GetIPInNetwork(network *dockertest.Network) string
	SetPolicy(*policyv2.Policy) error
	GetAllMapReponses() (map[types.NodeID][]tailcfg.MapResponse, error)
	PrimaryRoutes() (*routes.DebugRoutes, error)
	DebugBatcher() (*hscontrol.DebugBatcherInfo, error)
	DebugNodeStore() (map[types.NodeID]types.Node, error)
	DebugFilter() ([]tailcfg.FilterRule, error)
}
