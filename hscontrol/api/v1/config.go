package apiv1

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/config"
)

func init() {
	registrations = append(registrations, registerConfig)
}

type (
	getConfigInput struct {
		Docs bool `default:"true" doc:"Put each key's documentation above it, as comments." query:"docs"`
	}
	getConfigOutput struct {
		ContentType string `header:"Content-Type" hidden:"true"`
		Body        []byte
	}
)

func registerConfig(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "getConfig",
		Method:      http.MethodGet,
		Path:        "/api/v1/config",
		Summary:     "Get configuration",
		Description: "The configuration the server runs with, as a YAML configuration file without the client-only `cli` section. Secrets are redacted.",
		Tags:        []string{"Config"},
		Security:    bearerAuth,
		Responses: map[string]*huma.Response{
			"200": {
				Description: "OK",
				// No schema: a typed one makes the generated client parse
				// the document instead of returning it.
				Content: map[string]*huma.MediaType{"application/yaml": {}},
			},
		},
	}, func(_ context.Context, in *getConfigInput) (*getConfigOutput, error) {
		out, err := config.GenerateExample(b.Cfg, config.ExampleOptions{Docs: in.Docs, Redact: true, OmitClientOnly: true})
		if err != nil {
			return nil, huma.Error500InternalServerError("rendering configuration", err)
		}

		return &getConfigOutput{ContentType: "application/yaml", Body: out}, nil
	})
}
