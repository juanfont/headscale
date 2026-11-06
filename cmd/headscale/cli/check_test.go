package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSkipsInitConfig(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"check policy", []string{"check", "policy", "-f", "p"}, true},
		{"check config with config flag", []string{"-c", "x.yaml", "check", "config"}, true},
		{"check", []string{"check"}, true},
		{"policy get", []string{"policy", "get"}, false},
		{"nodes list", []string{"nodes", "list"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, skipsInitConfig(tt.args))
		})
	}
}
