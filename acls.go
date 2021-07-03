package headscale

import (
	"io"
	"os"

	"github.com/tailscale/hujson"
)

const errorInvalidPolicy = Error("invalid policy")

func (h *Headscale) ParsePolicy(path string) (*ACLPolicy, error) {
	policyFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer policyFile.Close()

	var policy ACLPolicy
	b, err := io.ReadAll(policyFile)
	if err != nil {
		return nil, err
	}
	err = hujson.Unmarshal(b, &policy)
	if policy.IsZero() {
		return nil, errorInvalidPolicy
	}

	return &policy, err
}
