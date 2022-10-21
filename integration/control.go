package integration

import v1 "github.com/juanfont/headscale/gen/go/headscale/v1"

type ControlServer interface {
	Shutdown() error
	GetHealthEndpoint() string
	GetEndpoint() string
	WaitForReady() error
	CreateNamespace(namespace string) error
	CreateAuthKey(namespace string) (*v1.PreAuthKey, error)
	ListNodes(namespace string) ([]*v1.Machine, error)
}
