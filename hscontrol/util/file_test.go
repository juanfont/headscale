package util

import (
	"io/fs"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestGetFileMode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want fs.FileMode
	}{
		{name: "plain octal", in: "770", want: 0o770},
		{name: "leading-zero octal", in: "0770", want: 0o770},
		{name: "go-style 0o prefix (viper default)", in: "0o770", want: 0o770},
		{name: "0o prefix fallback value", in: "0o700", want: 0o700},
		{name: "invalid falls back", in: "not-a-mode", want: PermissionFallback},
		{name: "empty falls back", in: "", want: PermissionFallback},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Set("unix_socket_permission", tt.in)
			t.Cleanup(func() {
				viper.Set("unix_socket_permission", "0o770")
			})

			assert.Equal(t, tt.want, GetFileMode("unix_socket_permission"))
		})
	}
}
