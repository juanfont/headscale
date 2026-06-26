package integration

import (
	"context"
	"net/netip"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/hscontrol"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/ory/dockertest/v3"
	"tailscale.com/tailcfg"
)

type ControlServer interface {
	Shutdown() (string, string, error)
	SaveLog(path string) (string, string, error)
	ReadLog() (string, string, error)
	SaveProfile(path string) error
	Execute(command []string) (string, error)
	WriteFile(path string, content []byte) error
	ConnectToNetwork(network *dockertest.Network) error
	GetHealthEndpoint() string
	GetEndpoint() string
	GetIPEndpoint() string
	CreateOAuthClient(ctx context.Context, scopes, tags []string) (string, string, error)
	WaitForRunning() error
	Restart() error
	CreateUser(user string) (*clientv1.User, error)
	CreateAuthKey(user uint64, reusable bool, ephemeral bool) (*clientv1.PreAuthKey, error)
	CreateAuthKeyWithTags(user uint64, reusable bool, ephemeral bool, tags []string) (*clientv1.PreAuthKey, error)
	CreateAuthKeyWithOptions(opts hsic.AuthKeyOptions) (*clientv1.PreAuthKey, error)
	DeleteAuthKey(id uint64) error
	ListNodes(users ...string) ([]*clientv1.Node, error)
	DeleteNode(nodeID uint64) error
	NodesByUser() (map[string][]*clientv1.Node, error)
	NodesByName() (map[string]*clientv1.Node, error)
	ListUsers() ([]*clientv1.User, error)
	MapUsers() (map[string]*clientv1.User, error)
	DeleteUser(userID uint64) error
	ApproveRoutes(nodeID uint64, routes []netip.Prefix) (*clientv1.Node, error)
	SetNodeTags(nodeID uint64, tags []string) error
	GetCert() []byte
	GetHostname() string
	GetIPInNetwork(network *dockertest.Network) string
	SetPolicy(pol *policyv2.Policy) error
	GetAllMapReponses() (map[types.NodeID][]tailcfg.MapResponse, error)
	PrimaryRoutes() (*types.DebugRoutes, error)
	DebugBatcher() (*hscontrol.DebugBatcherInfo, error)
	DebugNodeStore() (map[types.NodeID]types.Node, error)
	DebugFilter() ([]tailcfg.FilterRule, error)
}
