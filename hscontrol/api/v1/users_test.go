package apiv1

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/require"
)

type failSetUsers struct {
	policy.PolicyManager

	fail atomic.Int32
}

func (f *failSetUsers) SetUsers(users []types.User) (bool, bool, error) {
	if f.fail.Add(-1) >= 0 {
		return false, false, errors.New("injected SetUsers failure") //nolint:err113
	}

	return f.PolicyManager.SetUsers(users)
}

// TestRenameUserRefreshFails: /api/v1 answers a rename whose refresh of the
// policy failed after the commit with 500, as it always has, while /api/v0
// answers what was stored.
func TestRenameUserRefreshFails(t *testing.T) {
	cfg := config.Default()
	cfg.Database.Type = types.DatabaseSqlite
	cfg.Database.Sqlite.Path = t.TempDir() + "/headscale.db"
	cfg.Policy.Mode = types.PolicyModeDB
	cfg.Tuning.NodeStoreBatchTimeout = time.Millisecond

	st, err := state.NewState(&cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	key, _, err := st.CreateAPIKey(nil)
	require.NoError(t, err)

	router := chi.NewMux()
	NewAPI(router, Backend{State: st, Change: func(...change.Change) {}, Cfg: &cfg})

	alice := st.CreateUserForTest("alice")

	f := &failSetUsers{}
	f.fail.Store(1)
	st.WrapPolicyManagerForTest(func(pm policy.PolicyManager) policy.PolicyManager {
		f.PolicyManager = pm

		return f
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/user/"+strconv.FormatUint(uint64(alice.ID), 10)+"/rename/alicia", nil)
	req.Header.Set("Authorization", "Bearer "+key)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())

	stored, err := st.GetUserByID(types.UserID(alice.ID))
	require.NoError(t, err)
	require.Equal(t, "alicia", stored.Name, "the rename committed")
}
