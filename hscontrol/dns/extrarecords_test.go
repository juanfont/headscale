package dns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestNewExtraRecordsManagerReadsFormats(t *testing.T) {
	want := []tailcfg.DNSRecord{
		{Name: "grafana.example.com", Type: "A", Value: "100.64.0.3"},
		{Name: "prometheus.example.com", Type: "AAAA", Value: "fd7a:115c:a1e0::3"},
	}

	tests := []struct {
		name    string
		file    string
		content string
		wantErr bool
	}{
		{
			name: "json",
			file: "extra-records.json",
			content: `[
				{"name": "grafana.example.com", "type": "A", "value": "100.64.0.3"},
				{"name": "prometheus.example.com", "type": "AAAA", "value": "fd7a:115c:a1e0::3"}
			]`,
		},
		{
			name: "json with comments between entries",
			file: "extra-records.json",
			content: `[
				// monitoring dashboards
				{"name": "grafana.example.com", "type": "A", "value": "100.64.0.3"},
				/* metrics
				   backend */
				{"name": "prometheus.example.com", "type": "AAAA", "value": "fd7a:115c:a1e0::3"} // v6 only
			]`,
		},
		{
			name: "json with trailing commas",
			file: "extra-records.json",
			content: `[
				{"name": "grafana.example.com", "type": "A", "value": "100.64.0.3",},
				{"name": "prometheus.example.com", "type": "AAAA", "value": "fd7a:115c:a1e0::3"},
			]`,
		},
		{
			name: "hujson with comments",
			file: "extra-records.hujson",
			content: `[
				// monitoring dashboards
				{"name": "grafana.example.com", "type": "A", "value": "100.64.0.3"},
				{"name": "prometheus.example.com", "type": "AAAA", "value": "fd7a:115c:a1e0::3"},
			]`,
		},
		{
			name:    "json with unterminated comment",
			file:    "extra-records.json",
			content: `[{"name": "grafana.example.com", "type": "A", "value": "100.64.0.3"}] /*`,
			wantErr: true,
		},
		{
			name:    "json with object instead of list",
			file:    "extra-records.json",
			content: `{"name": "grafana.example.com", "type": "A", "value": "100.64.0.3"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.file)
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

			er, err := NewExtraRecordsManager(path)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			t.Cleanup(er.Close)

			assert.ElementsMatch(t, want, er.Records())
		})
	}
}
