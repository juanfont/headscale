package db

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestCredentialsEndAlike: auth keys, API keys and OAuth clients end the same
// way. A revoke refuses the credential at once and keeps its record with the
// first time; a revoke of nothing is the kind's not found; the removal takes
// every kind revoked before its cutoff, and keeps an auth key a node refers
// to.
func TestCredentialsEndAlike(t *testing.T) {
	test := func(t *testing.T, db *HSDatabase) {
		t.Helper()

		user, err := db.CreateUser(types.User{Name: "ends"})
		require.NoError(t, err)

		future := new(time.Now().Add(time.Hour))

		type kind struct {
			name     string
			create   func() (revoke func() error, refused func() error, id uint64)
			notFound func() error
			want     error
		}

		kinds := []kind{
			{
				name: "auth key",
				create: func() (func() error, func() error, uint64) {
					made, err := db.CreatePreAuthKey(user.TypedID(), true, false, future, nil)
					require.NoError(t, err)

					return func() error { return db.RevokePreAuthKey(made.ID) },
						func() error {
							k, err := db.GetPreAuthKey(made.Key)
							require.NoError(t, err)

							return k.Validate()
						}, made.ID
				},
				notFound: func() error { return db.RevokePreAuthKey(99999) },
				want:     ErrPreAuthKeyNotFound,
			},
			{
				name: "API key",
				create: func() (func() error, func() error, uint64) {
					secret, made, err := db.CreateAPIKey(future)
					require.NoError(t, err)

					return func() error { return db.RevokeAPIKey(made.ID) },
						func() error {
							_, err := db.AuthenticateAPIKey(secret)

							return err
						}, made.ID
				},
				notFound: func() error { return db.RevokeAPIKey(99999) },
				want:     ErrAPIKeyNotFound,
			},
			{
				name: "OAuth client",
				create: func() (func() error, func() error, uint64) {
					secret, made, err := db.CreateOAuthClient([]string{"auth_keys"}, []string{"tag:ci"}, "", nil)
					require.NoError(t, err)

					return func() error { return db.RevokeOAuthClient(made.ClientID) },
						func() error {
							_, err := db.AuthenticateOAuthClient(secret)

							return err
						}, made.ID
				},
				notFound: func() error { return db.RevokeOAuthClient("000000000000") },
				want:     ErrOAuthClientNotFound,
			},
		}

		revokedAt := func(id uint64) *time.Time {
			var c types.Credential
			require.NoError(t, db.DB.First(&c, "id = ?", id).Error)

			return c.Revoked
		}

		ids := make([]uint64, 0, len(kinds))

		var latest time.Time

		for _, k := range kinds {
			revoke, refused, id := k.create()
			require.NoError(t, refused(), "%s: valid before the revoke", k.name)
			require.NoError(t, revoke())
			require.Error(t, refused(), "%s: refused at once", k.name)

			first := revokedAt(id)
			require.NotNil(t, first)
			require.Zero(t, first.Nanosecond()%int(time.Microsecond), "%s: microseconds at most", k.name)

			require.NoError(t, revoke(), "%s: a repeated revoke", k.name)
			require.True(t, first.Equal(*revokedAt(id)), "%s: keeps its first time", k.name)

			require.ErrorIs(t, k.notFound(), k.want, k.name)

			ids = append(ids, id)
			latest = *first
		}

		inUse, err := db.CreatePreAuthKey(user.TypedID(), true, false, future, nil)
		require.NoError(t, err)
		require.NoError(t, db.DB.Create(&types.Node{Hostname: "joined", UserID: &user.ID, AuthKeyID: &inUse.ID}).Error)
		require.NoError(t, db.RevokePreAuthKey(inUse.ID))

		removed, err := db.DestroyRevokedCredentialsBefore(time.Now().Add(-time.Hour))
		require.NoError(t, err)
		require.Zero(t, removed, "revoked after the cutoff")

		removed, err = db.DestroyRevokedCredentialsBefore(latest.Add(time.Second))
		require.NoError(t, err)
		require.Equal(t, int64(len(ids)), removed, "every kind")

		for _, id := range ids {
			require.Nil(t, findCredential(t, db, id), "removed")
		}

		require.NotNil(t, revokedAt(inUse.ID), "a node refers to it")
	}

	t.Run("sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		test(t, db)
	})
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
}

// findCredential is the credential with id, or nil once it is removed.
func findCredential(t *testing.T, db *HSDatabase, id uint64) *types.Credential {
	t.Helper()

	var cs []types.Credential
	require.NoError(t, db.DB.Find(&cs, "id = ?", id).Error)

	if len(cs) == 0 {
		return nil
	}

	return &cs[0]
}

// makers are the credentials that can ask for a new one, each ended as its
// kind ends: an API key by its revoke, an access token by its client's.
func makers(t *testing.T, db *HSDatabase) []struct {
	name string
	id   uint64
	end  func() error
} {
	t.Helper()

	_, key, err := db.CreateAPIKey(new(time.Now().Add(time.Hour)))
	require.NoError(t, err)

	_, client, err := db.CreateOAuthClient([]string{"all"}, nil, "", nil)
	require.NoError(t, err)

	_, token, err := db.MintAccessToken(client.ClientID, []string{"all"}, nil, new(time.Now().Add(time.Hour)))
	require.NoError(t, err)

	_, orphanClient, err := db.CreateOAuthClient([]string{"all"}, nil, "", nil)
	require.NoError(t, err)

	_, orphan, err := db.MintAccessToken(orphanClient.ClientID, []string{"all"}, nil, new(time.Now().Add(time.Hour)))
	require.NoError(t, err)

	return []struct {
		name string
		id   uint64
		end  func() error
	}{
		{"API key", key.ID, func() error { return db.RevokeAPIKey(key.ID) }},
		{"access token", token.ID, func() error { return db.RevokeOAuthClient(client.ClientID) }},
		// A token that its client's revoke did not delete, as a mint that
		// raced the revoke once left: its client's end ends it.
		{"access token left by its client's revoke", orphan.ID, func() error {
			var row types.Credential
			require.NoError(t, db.DB.Take(&row, "id = ?", orphan.ID).Error)
			require.NoError(t, db.RevokeOAuthClient(orphanClient.ClientID))

			return db.DB.Create(&row).Error
		}},
	}
}

// creates makes each kind of credential for the maker with id, in its own
// transaction.
func creates(db *HSDatabase) map[string]func(maker uint64) error {
	return map[string]func(uint64) error{
		"auth key": func(maker uint64) error {
			return db.Write(func(tx *gorm.DB) error {
				_, _, err := CreatePreAuthKeyFrom(tx, NewPreAuthKey{Tags: []string{"tag:ci"}, Maker: maker})

				return err
			})
		},
		"API key": func(maker uint64) error {
			return db.Write(func(tx *gorm.DB) error {
				_, _, err := CreateAPIKeyFrom(tx, NewAPIKey{Maker: maker})

				return err
			})
		},
		"OAuth client": func(maker uint64) error {
			return db.Write(func(tx *gorm.DB) error {
				_, _, err := CreateOAuthClientFrom(tx, NewOAuthClient{Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"}, Maker: maker})

				return err
			})
		},
	}
}

func countCredentials(t *testing.T, db *HSDatabase) int64 {
	t.Helper()

	var n int64
	require.NoError(t, db.DB.Model(&types.Credential{}).Count(&n).Error)

	return n
}

// TestCredentialMadeByAnEndedCredential: a request authenticated before its
// credential ended makes no credential after the end answered. The write
// checks its maker in its own transaction.
func TestCredentialMadeByAnEndedCredential(t *testing.T) {
	test := func(t *testing.T, db *HSDatabase) {
		t.Helper()

		for _, m := range makers(t, db) {
			for kind, create := range creates(db) {
				require.NoError(t, create(m.id), "%s makes an %s while it is valid", m.name, kind)
			}

			require.NoError(t, m.end())

			before := countCredentials(t, db)

			for kind, create := range creates(db) {
				require.ErrorIs(t, create(m.id), ErrCredentialEnded, "%s ended, then an %s", m.name, kind)
			}

			require.Equal(t, before, countCredentials(t, db), "nothing was made")
		}

		for kind, create := range creates(db) {
			require.NoError(t, create(0), "the socket makes an %s", kind)
		}
	}

	t.Run("sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		test(t, db)
	})
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
}

// TestCredentialMakeWaitsForAnEnd: an end that has not committed holds the
// make that its credential asks for, which then refuses. The sequential case
// is TestCredentialMadeByAnEndedCredential.
func TestCredentialMakeWaitsForAnEnd(t *testing.T) {
	test := func(t *testing.T, db *HSDatabase) {
		t.Helper()

		_, key, err := db.CreateAPIKey(new(time.Now().Add(time.Hour)))
		require.NoError(t, err)

		_, client, err := db.CreateOAuthClient([]string{"all"}, nil, "", nil)
		require.NoError(t, err)

		_, token, err := db.MintAccessToken(client.ClientID, []string{"all"}, nil, new(time.Now().Add(time.Hour)))
		require.NoError(t, err)

		err = whileHeld(t, db,
			func(tx *gorm.DB) error {
				return revokeCredential(tx, types.CredentialAPIKey, "id = ?", key.ID, ErrAPIKeyNotFound)
			},
			func() error { return creates(db)["API key"](key.ID) })
		require.ErrorIs(t, err, ErrCredentialEnded, "an API key")

		err = whileHeld(t, db,
			func(tx *gorm.DB) error { return revokeOAuthClient(tx, client.ClientID) },
			func() error { return creates(db)["OAuth client"](token.ID) })
		require.ErrorIs(t, err, ErrCredentialEnded, "an access token")
	}

	t.Run("sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		test(t, db)
	})
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
}

// TestMintWaitsForARevoke: a revoke of a client that has not committed holds
// a mint for that client, which then refuses, so no token is minted after
// the revoke answered; and a credential that a token minted just before asks
// for is refused too.
func TestMintWaitsForARevoke(t *testing.T) {
	test := func(t *testing.T, db *HSDatabase) {
		t.Helper()

		_, client, err := db.CreateOAuthClient([]string{"all"}, nil, "", nil)
		require.NoError(t, err)

		err = whileHeld(t, db,
			func(tx *gorm.DB) error { return revokeOAuthClient(tx, client.ClientID) },
			func() error {
				_, _, err := db.MintAccessToken(client.ClientID, []string{"all"}, nil, new(time.Now().Add(time.Hour)))

				return err
			})
		require.ErrorIs(t, err, ErrOAuthClientRevoked)

		var tokens int64
		require.NoError(t, db.DB.Model(&types.Credential{}).Where("kind = ?", types.CredentialOAuthToken).Count(&tokens).Error)
		require.Zero(t, tokens, "no token outlives the revoke")
	}

	t.Run("sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		test(t, db)
	})
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
}

// whileHeld runs op while a transaction that hold wrote is open, and returns
// what op answers once the transaction committed. op must wait for it: on
// PostgreSQL for a row lock, on SQLite for its one connection. That is seen
// in the database, not timed, and an op that answers before is a failure.
func whileHeld(t *testing.T, db *HSDatabase, hold func(tx *gorm.DB) error, op func() error) error {
	t.Helper()

	return whileHeldThen(t, db, hold, op, nil)
}

// whileHeldThen is [whileHeld] where then, when set, writes in the
// transaction once op waits, before it commits.
func whileHeldThen(t *testing.T, db *HSDatabase, hold func(tx *gorm.DB) error, op func() error, then func(tx *gorm.DB) error) error {
	t.Helper()

	sqlDB, err := db.DB.DB()
	require.NoError(t, err)

	tx := db.DB.Begin()
	require.NoError(t, tx.Error)
	require.NoError(t, hold(tx))

	waitsBefore := sqlDB.Stats().WaitCount
	waiting := func() bool {
		if db.cfg.Database.Type != types.DatabasePostgres {
			return sqlDB.Stats().WaitCount > waitsBefore
		}

		var n int64
		require.NoError(t, db.DB.Raw(
			"SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'",
		).Scan(&n).Error)

		return n > 0
	}

	done := make(chan error, 1)

	go func() { done <- op() }()

	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()

	deadline := time.After(30 * time.Second)

	for !waiting() {
		select {
		case err := <-done:
			tx.Rollback()
			t.Fatalf("answered while the transaction was open: %v", err)
		case <-deadline:
			tx.Rollback()
			t.Fatal("neither waited nor answered")
		case <-tick.C:
		}
	}

	if then != nil {
		require.NoError(t, then(tx))
	}

	require.NoError(t, tx.Commit().Error)

	return <-done
}

// TestCredentialLockOrder: every write that locks a client and its tokens
// takes the client first, so a revoke, a mint, the holds of a token and the
// two removal jobs at once never deadlock. Only PostgreSQL locks rows;
// SQLite runs one writer at a time.
func TestCredentialLockOrder(t *testing.T) {
	db := newPostgresTestDB(t)

	hour := new(time.Now().Add(time.Hour))

	for round := range 30 {
		_, client, err := db.CreateOAuthClient([]string{"all"}, nil, "", nil)
		require.NoError(t, err)

		_, token, err := db.MintAccessToken(client.ClientID, []string{"all"}, nil, hour)
		require.NoError(t, err)

		ops := make([]func() error, 0, 11)
		ops = append(ops,
			func() error { return db.RevokeOAuthClient(client.ClientID) },
			func() error {
				_, err := db.DestroyRevokedCredentialsBefore(time.Now().Add(time.Hour))

				return err
			},
			func() error {
				_, err := db.DeleteExpiredAccessTokens(time.Now().Add(2 * time.Hour))

				return err
			})

		for range 4 {
			ops = append(ops,
				func() error { return creates(db)["OAuth client"](token.ID) },
				func() error {
					_, _, err := db.MintAccessToken(client.ClientID, []string{"all"}, nil, hour)

					return err
				})
		}

		errs := make(chan error, len(ops))

		var wg sync.WaitGroup
		for _, op := range ops {
			wg.Go(func() { errs <- op() })
		}

		wg.Wait()
		close(errs)

		for err := range errs {
			if err != nil {
				require.NotContains(t, err.Error(), "deadlock", "round %d", round)
			}
		}
	}
}

// pgWaiting reports whether n or more statements wait for a lock.
func pgWaiting(t *testing.T, db *HSDatabase, n int64) bool {
	t.Helper()

	var got int64

	require.NoError(t, db.DB.Raw(
		"SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'",
	).Scan(&got).Error)

	return got >= n
}

// revokeLongAgo revokes the credentials ids two days back.
func revokeLongAgo(t *testing.T, db *HSDatabase, ids ...uint64) {
	t.Helper()

	require.NoError(t, db.DB.Model(&types.Credential{}).Where("id IN ?", ids).
		Update("revoked", time.Now().Add(-48*time.Hour).UTC()).Error)
}

// TestRevokedRemovalBesideAUserDelete: the hourly removal of revoked
// credentials never waits for a row, so it cannot deadlock with the delete
// of a user, whatever rows the delete locks and in whichever order. The
// user made a tagged key and a client and owns an API key, all revoked, the
// ones it made first; the delete holds the user and its key; the removal
// takes what the user made, skips the key and ends without waiting; the
// delete then clears what the user made (gone) and removes the key, which
// it reported. No timing: the test
// steps the delete's transaction by hand.
func TestRevokedRemovalBesideAUserDelete(t *testing.T) {
	db := newPostgresTestDB(t)

	user := db.CreateUserForTest("victim")
	uid := types.UserID(user.ID)

	// What the user made: a tagged key (created_by_user_id) and a client
	// (user_id); what it owns: an API key, made last.
	var (
		tagged      *types.PreAuthKey
		client, key *types.Credential
	)

	require.NoError(t, db.Write(func(tx *gorm.DB) error {
		var err error

		tagged, _, err = CreatePreAuthKeyFrom(tx, NewPreAuthKey{Tags: []string{"tag:ci"}, CreatedBy: &uid})
		if err != nil {
			return err
		}

		client, _, err = CreateOAuthClientFrom(tx, NewOAuthClient{Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"}, CreatedBy: &uid})
		if err != nil {
			return err
		}

		key, _, err = CreateAPIKeyFrom(tx, NewAPIKey{Owner: &uid})

		return err
	}))
	require.Less(t, client.ID, key.ID)
	revokeLongAgo(t, db, tagged.ID, client.ID, key.ID)

	tx := db.DB.Begin()
	defer tx.Rollback()

	c, err := LockUserContents(tx, uid)
	require.NoError(t, err)
	require.Equal(t, []uint64{key.ID}, c.APIKeys)

	type removal struct {
		n   int64
		err error
	}

	removed := make(chan removal, 1)

	go func() {
		n, err := db.DestroyRevokedCredentialsBefore(time.Now())
		removed <- removal{n, err}
	}()

	// Until the removal ends or waits; a removal that waits is then met
	// by the delete, as the hourly job is in production.
	var (
		r      removal
		ended  bool
		waited bool
	)

	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()

	deadline := time.After(30 * time.Second)

	for !ended && !waited {
		select {
		case r = <-removed:
			ended = true
		case <-tick.C:
			waited = pgWaiting(t, db, 1)
		case <-deadline:
			t.Fatal("the removal neither ended nor waited")
		}
	}

	require.NoError(t, DestroyUserContents(tx, c), "the delete is not aborted")
	require.NoError(t, tx.Commit().Error)

	if !ended {
		r = <-removed
	}

	require.NoError(t, r.err, "the removal is not aborted")
	require.False(t, waited, "the removal waited for a row")
	require.Equal(t, int64(2), r.n, "the removal takes what the user made and leaves the held key")

	var left int64

	require.NoError(t, db.DB.Model(&types.Credential{}).Where("id IN ?", []uint64{tagged.ID, client.ID, key.ID}).Count(&left).Error)
	require.Zero(t, left)
}

// TestRevokedRemovalSkipsAHeldRow: a revoked row that another transaction
// holds is left, and the next run removes it.
func TestRevokedRemovalSkipsAHeldRow(t *testing.T) {
	db := newPostgresTestDB(t)

	ids := make([]uint64, 2)

	for i := range ids {
		require.NoError(t, db.Write(func(tx *gorm.DB) error {
			k, _, err := CreateAPIKeyFrom(tx, NewAPIKey{})
			ids[i] = k.ID

			return err
		}))
	}

	revokeLongAgo(t, db, ids...)

	hold := db.DB.Begin()
	require.NoError(t, hold.Exec("SELECT id FROM credentials WHERE id = ? FOR UPDATE", ids[0]).Error)

	n, err := db.DestroyRevokedCredentialsBefore(time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "the held row is skipped, not waited for")

	require.NoError(t, hold.Commit().Error)

	n, err = db.DestroyRevokedCredentialsBefore(time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "the next run removes it")
}

// TestRevokedRemovalInPieces: a backlog of more revoked rows than one
// statement may bind on either database (SQLite 32766, PostgreSQL 65535) is
// removed whole, a piece at a time.
func TestRevokedRemovalInPieces(t *testing.T) {
	eachDB(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		const backlog = 1<<16 + 1

		revoked := time.Now().Add(-48 * time.Hour).UTC()

		rows := make([]types.Credential, backlog)
		for i := range rows {
			rows[i] = types.Credential{Kind: types.CredentialAPIKey, Identifier: "backlog" + strconv.Itoa(i), Hash: []byte("$x"), Revoked: &revoked}
		}

		require.NoError(t, db.DB.CreateInBatches(&rows, 500).Error)

		n, err := db.DestroyRevokedCredentialsBefore(time.Now())
		require.NoError(t, err)
		require.Equal(t, int64(backlog), n)

		var left int64

		require.NoError(t, db.DB.Model(&types.Credential{}).Count(&left).Error)
		require.Zero(t, left)
	})
}
