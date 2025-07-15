package cli

import (
	"context"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// WithClient handles gRPC client setup and cleanup, calls fn with client and context
func WithClient(fn func(context.Context, v1.HeadscaleServiceClient) error) error {
	ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
	defer cancel()
	defer conn.Close()

	return fn(ctx, client)
}
