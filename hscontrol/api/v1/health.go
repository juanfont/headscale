package apiv1

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// HealthResponseBody mirrors the v1 HealthResponse message. database_connectivity
// is reported true only when the database responds to a ping.
type HealthResponseBody struct {
	DatabaseConnectivity bool `json:"databaseConnectivity"`
}

type healthOutput struct {
	Body HealthResponseBody
}

func init() {
	registrations = append(registrations, registerHealth)
}

func registerHealth(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "health",
		Method:      http.MethodGet,
		Path:        "/api/v1/health",
		Summary:     "Health check",
		Description: "Reports server health, including database connectivity.",
		Tags:        []string{"Health"},
		Security:    bearerAuth,
	}, func(ctx context.Context, _ *struct{}) (*healthOutput, error) {
		err := b.State.PingDB(ctx)
		if err != nil {
			return nil, mapError("pinging database", err)
		}

		return &healthOutput{Body: HealthResponseBody{DatabaseConnectivity: true}}, nil
	})
}
