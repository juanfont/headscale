package cli

import (
	"errors"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestUsernameAndIDFromFlag(t *testing.T) {
	newCmd := func() *cobra.Command {
		cmd := &cobra.Command{}
		cmd.Flags().StringP("name", "n", "", "")
		cmd.Flags().Int64P("identifier", "i", -1, "")

		return cmd
	}

	t.Run("neither flag is required", func(t *testing.T) {
		_, _, err := usernameAndIDFromFlag(newCmd())
		if !errors.Is(err, errFlagRequired) {
			t.Fatalf("want errFlagRequired, got %v", err)
		}
	})

	t.Run("name only", func(t *testing.T) {
		cmd := newCmd()
		_ = cmd.Flags().Set("name", "alice")

		id, name, err := usernameAndIDFromFlag(cmd)
		if err != nil || id != 0 || name != "alice" {
			t.Fatalf("got id=%d name=%q err=%v", id, name, err)
		}
	})

	t.Run("id only", func(t *testing.T) {
		cmd := newCmd()
		_ = cmd.Flags().Set("identifier", "7")

		id, name, err := usernameAndIDFromFlag(cmd)
		if err != nil || id != 7 || name != "" {
			t.Fatalf("got id=%d name=%q err=%v", id, name, err)
		}
	})
}

func TestApiKeyIDOrPrefix(t *testing.T) {
	newCmd := func() *cobra.Command {
		cmd := &cobra.Command{}
		cmd.Flags().Uint64P("id", "i", 0, "")
		cmd.Flags().StringP("prefix", "p", "", "")

		return cmd
	}

	t.Run("neither is an error", func(t *testing.T) {
		_, _, err := apiKeyIDOrPrefix(newCmd())
		if !errors.Is(err, errMissingParameter) {
			t.Fatalf("want errMissingParameter, got %v", err)
		}
	})

	t.Run("both is an error", func(t *testing.T) {
		cmd := newCmd()
		_ = cmd.Flags().Set("id", "1")
		_ = cmd.Flags().Set("prefix", "abc")

		_, _, err := apiKeyIDOrPrefix(cmd)
		if !errors.Is(err, errMissingParameter) {
			t.Fatalf("want errMissingParameter, got %v", err)
		}
	})

	t.Run("id only", func(t *testing.T) {
		cmd := newCmd()
		_ = cmd.Flags().Set("id", "5")

		id, prefix, err := apiKeyIDOrPrefix(cmd)
		if err != nil || id != 5 || prefix != "" {
			t.Fatalf("got id=%d prefix=%q err=%v", id, prefix, err)
		}
	})
}

func TestExpirationFromFlag(t *testing.T) {
	newCmd := func() *cobra.Command {
		cmd := &cobra.Command{}
		cmd.Flags().StringP("expiration", "e", "", "")

		return cmd
	}

	t.Run("empty is unset", func(t *testing.T) {
		exp, err := expirationFromFlag(newCmd())
		if err != nil || exp.Set {
			t.Fatalf("want unset, got set=%v err=%v", exp.Set, err)
		}
	})

	t.Run("invalid duration is an error", func(t *testing.T) {
		cmd := newCmd()
		_ = cmd.Flags().Set("expiration", "not-a-duration")

		_, err := expirationFromFlag(cmd)
		if err == nil {
			t.Fatal("want error for invalid duration")
		}
	})

	t.Run("valid duration is in the future", func(t *testing.T) {
		cmd := newCmd()
		_ = cmd.Flags().Set("expiration", "1h")

		exp, err := expirationFromFlag(cmd)
		if err != nil || !exp.Set {
			t.Fatalf("want set, got set=%v err=%v", exp.Set, err)
		}

		if !exp.Value.After(time.Now()) {
			t.Errorf("expiration not in the future: %v", exp.Value)
		}
	})
}
