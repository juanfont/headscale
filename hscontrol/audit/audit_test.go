package audit

import (
	"context"
	"testing"
)

func TestActorFromContext(t *testing.T) {
	ctx := WithActor(context.Background(), "api-key:abc123")

	if got := ActorFromContext(ctx); got != "api-key:abc123" {
		t.Fatalf("got %q want api-key:abc123", got)
	}

	if got := ActorFromContext(context.Background()); got != ActorSystem {
		t.Fatalf("default actor: got %q want %q", got, ActorSystem)
	}

	// An empty actor falls back to "system".
	if got := ActorFromContext(WithActor(context.Background(), "")); got != ActorSystem {
		t.Fatalf("empty actor: got %q want %q", got, ActorSystem)
	}
}

func TestLocalActorFallback(t *testing.T) {
	ctx := WithActor(context.Background(), ActorLocal)

	if got := ActorFromContext(ctx); got != ActorLocal {
		t.Fatalf("got %q want %q", got, ActorLocal)
	}
}
