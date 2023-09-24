package integration

import (
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/ory/dockertest/v3"
)

type ControlServer interface {
	Shutdown() error
	SaveLog(string) error
	SaveProfile(string) error
	Execute(command []string) (string, error)
	ConnectToNetwork(network *dockertest.Network) error
	GetHealthEndpoint() string
	GetEndpoint() string
	WaitForRunning() error
	CreateUser(user string) error
	CreateAuthKey(user string, reusable bool, ephemeral bool) (*v1.PreAuthKey, error)
	ListNodesInUser(user string) ([]*v1.Node, error)
	GetCert() []byte
	GetHostname() string
	GetIP() string
}
