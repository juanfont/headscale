package apiv1

import (
	"context"

	oas "github.com/juanfont/headscale/gen/api/v1"
)

// Health reports server health, including database connectivity. A failed
// database ping is a 500; the previous implementation likewise returned the ping
// error (the body's databaseConnectivity flag was never observable on failure).
func (s *Server) Health(ctx context.Context) (*oas.HealthOK, error) {
	err := s.state.PingDB(ctx)
	if err != nil {
		return nil, internalError("pinging database: " + err.Error())
	}

	return &oas.HealthOK{DatabaseConnectivity: oas.NewOptBool(true)}, nil
}
