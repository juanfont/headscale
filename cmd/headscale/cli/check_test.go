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
		{"check policy with config flag", []string{"-c", "x.yaml", "check", "policy"}, true},
		{"check", []string{"check"}, true},
		{"help check policy", []string{"help", "check", "policy"}, true},
		{"policy get", []string{"policy", "get"}, false},
		{"help nodes", []string{"help", "nodes"}, false},
		{"nodes list", []string{"nodes", "list"}, false},
	}

	// Execute adds the help command; these tests call Find without it.
	rootCmd.InitDefaultHelpCmd()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, skipsInitConfig(tt.args))
		})
	}
}
