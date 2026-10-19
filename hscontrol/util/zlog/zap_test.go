package zlog

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestZap(t *testing.T) {
	var buf bytes.Buffer

	logger := Zap(zerolog.New(&buf).Level(zerolog.InfoLevel)).
		Named("acme").
		With(zap.String("issuer", "letsencrypt"))

	logger.Debug("below the logger's level")
	logger.Warn("renewing", zap.Int("attempt", 2))

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got), buf.String())
	assert.Equal(t, map[string]any{
		"level":   "warn",
		"logger":  "acme",
		"issuer":  "letsencrypt",
		"attempt": float64(2),
		"message": "renewing",
	}, got)
}
