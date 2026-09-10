package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/spf13/cobra"
)

// filterUsersServer serves GET /api/v1/user responses filtered like the
// real API: by the id, name, and email query parameters.
func filterUsersServer(t *testing.T, users []clientv1.User) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		filtered := make([]clientv1.User, 0, len(users))
		for _, user := range users {
			if name := query.Get("name"); name != "" && user.Name != name {
				continue
			}

			if id := query.Get("id"); id != "" && user.Id != id {
				continue
			}

			if email := query.Get("email"); email != "" && user.Email != email {
				continue
			}

			filtered = append(filtered, user)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		err := json.NewEncoder(w).Encode(clientv1.ListUsersOutputBody{Users: filtered})
		if err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
}

func commandWithUserFlags(t *testing.T, identifier, name string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	usernameAndIDFlag(cmd)

	if identifier != "" {
		err := cmd.Flags().Set("identifier", identifier)
		if err != nil {
			t.Fatalf("setting identifier flag: %v", err)
		}
	}

	if name != "" {
		err := cmd.Flags().Set("name", name)
		if err != nil {
			t.Fatalf("setting name flag: %v", err)
		}
	}

	return cmd
}

func TestResolveSingleUser(t *testing.T) {
	lukas := clientv1.User{Id: "6", Name: "lukas", Email: "login@lukasrunge.de"}
	hannes := clientv1.User{Id: "9", Name: "hannes@rueger.events", Email: "hannes@rueger.events"}
	hannesDup := clientv1.User{Id: "10", Name: "hannes@rueger.events", Email: "other@example.com"}

	tests := []struct {
		name       string
		users      []clientv1.User
		identifier string
		flagName   string
		wantId     string
		wantErr    bool
		wantErrIs  error
	}{
		{
			// Regression: renaming by name used to return the raw flag
			// id (0 when unset), so the rename request targeted user 0.
			name:     "resolves by name to the matched user's identifier",
			users:    []clientv1.User{lukas, hannes},
			flagName: "hannes@rueger.events",
			wantId:   "9",
		},
		{
			name:       "resolves by identifier",
			users:      []clientv1.User{hannes},
			identifier: "9",
			wantId:     "9",
		},
		{
			// Regression: zero matches used to be reported as
			// "multiple users match query".
			name:      "no match is a not-found error",
			users:     []clientv1.User{lukas},
			flagName:  "nobody@example.com",
			wantErr:   true,
			wantErrIs: errUserNotFound,
		},
		{
			// OIDC users can share a name, see issue #3429.
			name:      "multiple matches are an ambiguity error",
			users:     []clientv1.User{hannes, hannesDup},
			flagName:  "hannes@rueger.events",
			wantErr:   true,
			wantErrIs: errMultipleUsersMatch,
		},
		{
			// Regression: --identifier 0 was sent to the API as "no
			// filter", listing every user and failing as ambiguous.
			name:       "identifier zero is rejected before calling the API",
			users:      []clientv1.User{lukas, hannes},
			identifier: "0",
			wantErr:    true,
			wantErrIs:  errInvalidIdentifier,
		},
		{
			name:      "no flags is a usage error",
			users:     []clientv1.User{lukas},
			wantErr:   true,
			wantErrIs: errFlagRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := filterUsersServer(t, tt.users)
			defer server.Close()

			client, err := clientv1.NewClientWithResponses(server.URL)
			if err != nil {
				t.Fatalf("creating client: %v", err)
			}

			cmd := commandWithUserFlags(t, tt.identifier, tt.flagName)

			id, user, err := resolveSingleUser(context.Background(), client, cmd)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveSingleUser() error = nil, want error")
				}

				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("resolveSingleUser() error = %v, want %v", err, tt.wantErrIs)
				}

				return
			}

			if err != nil {
				t.Fatalf("resolveSingleUser() error = %v", err)
			}

			if id != tt.wantId {
				t.Errorf("resolveSingleUser() id = %q, want %q", id, tt.wantId)
			}

			if user.Id != tt.wantId {
				t.Errorf("resolveSingleUser() user.Id = %q, want %q", user.Id, tt.wantId)
			}
		})
	}
}
