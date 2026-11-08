package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestExtractDocs(t *testing.T) {
	fields, values, err := extractDocs("testdata/fixture.go.txt")
	require.NoError(t, err)

	tests := []struct {
		name string
		got  map[string]string
		want map[string]string
	}{
		{
			name: "fields",
			got:  fields,
			want: map[string]string{
				"Server.Addr":     "The host:port the server listens on.",
				"Server.Commands": "Run in order:\n\n\tfirst command\n\tsecond command",
				"Server.Enabled":  "Lets nodes connect.",
				"Server.Notes":    "Two paragraphs, still the first.\n\nThe second paragraph.",
				"Server.Choices":  "Listed:\n\n  - first choice\n  - second choice\n\nRun:\n\n\tfirst command\n\t  indented more",
				"Server.Retries":  "How often to retry; Retries is not the first word.",
			},
		},
		{
			name: "values",
			got:  values,
			want: map[string]string{
				"Mode=fast":  "The quick path.",
				"Mode=slow":  "Takes its time.",
				"Mode=paren": "Has its type in parentheses.",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.got); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtractDocsErrors(t *testing.T) {
	const enum = "package fixture\n\ntype Mode string\n\nfunc (Mode) Allowed() []string { return nil }\n\n"

	tests := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name:    "enum value is an expression",
			src:     enum + "const (\n\t// ModeSlow is slow.\n\tModeSlow Mode = \"sl\" + \"ow\"\n)\n",
			wantErr: "constant ModeSlow: value must be a string literal with an explicit type",
		},
		{
			name:    "enum type is inferred",
			src:     enum + "const (\n\t// ModeAlias is an alias.\n\tModeAlias = Mode(\"alias\")\n)\n",
			wantErr: "constant ModeAlias: value must be a string literal with an explicit type",
		},
		{
			name:    "enum conversion in parentheses",
			src:     enum + "const (\n\t// ModeParen is in parentheses.\n\tModeParen = (Mode(\"paren\"))\n)\n",
			wantErr: "constant ModeParen: value must be a string literal with an explicit type",
		},
		{
			name:    "opening paragraph is only the Go name",
			src:     "package fixture\n\ntype Server struct {\n\t// Choices are\n\t//\n\t//\tfirst command\n\t//\tsecond command\n\tChoices string `koanf:\"choices\"`\n}\n",
			wantErr: "Server.Choices: doc comment says nothing after the Go name",
		},
		{
			name:    "doc is only the Go name",
			src:     "package fixture\n\ntype Server struct {\n\t// Addr is\n\tAddr string `koanf:\"addr\"`\n}\n",
			wantErr: "Server.Addr: doc comment says nothing after the Go name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.go")
			require.NoError(t, os.WriteFile(path, []byte(tt.src), 0o600))

			_, _, err := extractDocs(path)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// TestGenerate: the output file is not an input, so a conflicted or
// deleted table regenerates; a broken source file still fails.
func TestGenerate(t *testing.T) {
	fixture, err := os.ReadFile("testdata/fixture.go.txt")
	require.NoError(t, err)

	clean := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(clean, "fixture.go"), fixture, 0o600))

	want, err := table(clean, filepath.Join(clean, "docs_generated.go"))
	require.NoError(t, err)

	const conflicted = "<<<<<<< HEAD\npackage types\n=======\n>>>>>>> other\n"

	tests := []struct {
		name    string
		files   map[string]string // besides fixture.go
		wantErr string
	}{
		{name: "deleted output"},
		{name: "conflicted output", files: map[string]string{"docs_generated.go": conflicted}},
		{name: "conflicted source", files: map[string]string{"other.go": conflicted}, wantErr: "other.go"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "fixture.go"), fixture, 0o600))

			for name, src := range tt.files {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600))
			}

			out := filepath.Join(dir, "docs_generated.go")

			err := generate(dir, out)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			got, err := os.ReadFile(out)
			require.NoError(t, err)

			if diff := cmp.Diff(string(want), string(got)); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func TestTableFresh(t *testing.T) {
	got, err := table("../../hscontrol/types", "../../hscontrol/types/config_docs_generated.go")
	require.NoError(t, err)

	want, err := os.ReadFile("../../hscontrol/types/config_docs_generated.go")
	require.NoError(t, err)

	if diff := cmp.Diff(string(want), string(got)); diff != "" {
		t.Errorf("hscontrol/types/config_docs_generated.go is stale, run go generate ./hscontrol/types/ (-committed +extracted):\n%s", diff)
	}
}
