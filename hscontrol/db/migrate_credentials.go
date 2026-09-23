package db

import (
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// credentialsDDLSQLite matches schema.sql byte-for-byte (the squibble digest is
// the SQLite source of truth). Only revoked legacy rows may lack a hash, and
// every stored hash format ($sha256$, $argon2id$, bcrypt $2a$) starts with '$'.
// TODO(kradalby): in 0.31, with the credentials migration, tighten
// chk_credentials_hash to hash NOT NULL (needs a migration clearing the
// hashless revoked rows).
//
//nolint:gosec // DDL, not a credential
const credentialsDDLSQLite = `CREATE TABLE credentials(
  id integer PRIMARY KEY AUTOINCREMENT,
  kind text NOT NULL CHECK(kind IN ('api','authkey','oauth_client','oauth_token')),
  identifier text,
  hash blob,
  user_id integer,
  description text,
  scopes text,
  tags text,
  reusable numeric,
  ephemeral numeric DEFAULT false,
  used numeric DEFAULT false,
  last_seen datetime,
  client_id text,
  created_at datetime,
  expiration datetime,
  revoked datetime,

  CONSTRAINT fk_credentials_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT chk_credentials_hash CHECK(hash IS NOT NULL OR revoked IS NOT NULL),
  CONSTRAINT chk_credentials_hash_format CHECK(hash IS NULL OR substr(CAST(hash AS TEXT), 1, 1) = '$')
)`

// credentialsDDLPostgres is the Postgres form of [credentialsDDLSQLite]; both
// InitSchema and the migration use it, so fresh and upgraded databases match.
//
//nolint:gosec // DDL, not a credential
const credentialsDDLPostgres = `CREATE TABLE credentials(
  id bigserial PRIMARY KEY,
  kind text NOT NULL CHECK(kind IN ('api','authkey','oauth_client','oauth_token')),
  identifier text,
  hash bytea,
  user_id bigint,
  description text,
  scopes text,
  tags text,
  reusable boolean,
  ephemeral boolean DEFAULT false,
  used boolean DEFAULT false,
  last_seen timestamptz,
  client_id text,
  created_at timestamptz,
  expiration timestamptz,
  revoked timestamptz,

  CONSTRAINT fk_credentials_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT chk_credentials_hash CHECK(hash IS NOT NULL OR revoked IS NOT NULL),
  CONSTRAINT chk_credentials_hash_format CHECK(hash IS NULL OR substring(hash from 1 for 1) = '\x24'::bytea)
)`

// credentialIndexes are created with the table.
var credentialIndexes = []string{
	`CREATE UNIQUE INDEX idx_credentials_identifier ON credentials(kind, identifier)`,
	`CREATE INDEX idx_credentials_user_id ON credentials(user_id)`,
}

// ensureCredentialsTable creates the credentials table and its indexes in one
// transaction, and is a no-op once the table exists. InitSchema's records are
// written after it runs, so an interrupted first start re-runs it.
func ensureCredentialsTable(tx *gorm.DB) error {
	if tx.Migrator().HasTable(&types.Credential{}) {
		return nil
	}

	return tx.Transaction(createCredentialsTable)
}

// createCredentialsTable creates the unified credentials table and its indexes.
func createCredentialsTable(tx *gorm.DB) error {
	ddl := credentialsDDLSQLite
	if tx.Name() != "sqlite" {
		ddl = credentialsDDLPostgres
	}

	err := tx.Exec(ddl).Error
	if err != nil {
		return fmt.Errorf("creating credentials table: %w", err)
	}

	for _, stmt := range credentialIndexes {
		err := tx.Exec(stmt).Error
		if err != nil {
			return fmt.Errorf("creating credentials index: %w", err)
		}
	}

	return nil
}

// migrateToCredentials backfills the unified credentials table from the four
// per-kind tables and drops them. Pre-auth keys keep their ids so
// nodes.auth_key_id stays valid; the nodes FK is then retargeted to
// credentials(id). The caller runs it in one transaction, so a failure leaves
// the database untouched and the migration can be retried.
//
// TODO(kradalby): remove in 0.31 with the credentials migration.
func migrateToCredentials(tx *gorm.DB) error {
	// user_id on api_keys and oauth_clients never had a foreign key and
	// DestroyUser left it behind, so it can reference a deleted user. Null it
	// rather than fail the new foreign key.
	const ownerOrNull = `CASE WHEN user_id IN (SELECT id FROM users) THEN user_id END`

	// A row without a hash can never authenticate; keep it revoked rather
	// than drop it, so references to it stay valid.
	const revokedIfNoHash = `CASE WHEN hash IS NULL THEN CURRENT_TIMESTAMP END`

	// Legacy plaintext pre-auth keys (no prefix) land as hashless revoked
	// placeholders here; hashLegacyPreAuthKeys then hashes the ones that still
	// carry their key so they keep working.
	err := tx.Exec(`INSERT INTO credentials
  (id, kind, identifier, hash, user_id, description, reusable, ephemeral, used, tags, expiration, revoked, created_at)
SELECT id, ?,
  CASE WHEN prefix IS NULL OR prefix = '' THEN 'legacy-id-' || id ELSE prefix END,
  CASE WHEN prefix IS NULL OR prefix = '' THEN NULL ELSE hash END,
  `+ownerOrNull+`, description, reusable, ephemeral, used, tags, expiration,
  CASE WHEN prefix IS NULL OR prefix = '' OR hash IS NULL
    THEN COALESCE(revoked, CURRENT_TIMESTAMP) ELSE revoked END,
  created_at
FROM pre_auth_keys`, types.CredentialPreAuthKey).Error
	if err != nil {
		return fmt.Errorf("backfilling pre-auth keys: %w", err)
	}

	err = hashLegacyPreAuthKeys(tx)
	if err != nil {
		return err
	}

	// Continue the pre-auth key id sequence, not just max(id): ids of deleted
	// keys must not be handed out again, or a stale request by id would hit a
	// new key. This also moves Postgres past the explicit-id inserts above.
	err = continuePreAuthKeySequence(tx)
	if err != nil {
		return err
	}

	err = tx.Exec(`INSERT INTO credentials (kind, identifier, hash, user_id, last_seen, expiration, revoked, created_at)
SELECT ?, prefix, hash, `+ownerOrNull+`, last_seen, expiration, `+revokedIfNoHash+`, created_at
FROM api_keys ORDER BY id`, types.CredentialAPIKey).Error
	if err != nil {
		return fmt.Errorf("backfilling api keys: %w", err)
	}

	err = tx.Exec(`INSERT INTO credentials (kind, identifier, hash, scopes, tags, description, user_id, revoked, created_at)
SELECT ?, client_id, secret_hash, scopes, tags, description, `+ownerOrNull+`,
  CASE WHEN secret_hash IS NULL THEN COALESCE(revoked, CURRENT_TIMESTAMP) ELSE revoked END, created_at
FROM oauth_clients ORDER BY id`, types.CredentialOAuthClient).Error
	if err != nil {
		return fmt.Errorf("backfilling oauth clients: %w", err)
	}

	err = tx.Exec(`INSERT INTO credentials (kind, identifier, hash, client_id, scopes, tags, expiration, revoked, created_at)
SELECT ?, prefix, hash, client_id, scopes, tags, expiration, `+revokedIfNoHash+`, created_at
FROM oauth_access_tokens ORDER BY id`, types.CredentialOAuthToken).Error
	if err != nil {
		return fmt.Errorf("backfilling oauth access tokens: %w", err)
	}

	err = retargetNodesAuthKeyFK(tx)
	if err != nil {
		return err
	}

	err = tx.Exec(`CREATE INDEX idx_nodes_auth_key_id ON nodes(auth_key_id)`).Error
	if err != nil {
		return fmt.Errorf("creating nodes auth_key_id index: %w", err)
	}

	for _, table := range []string{"pre_auth_keys", "api_keys", "oauth_clients", "oauth_access_tokens"} {
		err := tx.Migrator().DropTable(table)
		if err != nil {
			return fmt.Errorf("dropping %s: %w", table, err)
		}
	}

	return nil
}

// hashLegacyPreAuthKeys stores each pre-0.28 plaintext pre-auth key as a SHA-256
// hash under its derived identifier (see [legacyAuthKeyIdentifier]) and lifts
// the placeholder revocation, so the key keeps authenticating after the
// upgrade. They hold 192 bits of crypto/rand entropy, so the reasoning at
// [hashPrefixSHA256] applies. SQLite has no SHA-256 function, so this runs in Go.
//
// TODO(kradalby): remove in 0.31 with the credentials migration.
func hashLegacyPreAuthKeys(tx *gorm.DB) error {
	type legacyKey struct {
		ID  uint64
		Key string
	}

	var keys []legacyKey

	err := tx.Raw(`SELECT id, key FROM pre_auth_keys
WHERE (prefix IS NULL OR prefix = '') AND key IS NOT NULL AND key != ''`).
		Scan(&keys).Error
	if err != nil {
		return fmt.Errorf("reading legacy pre-auth keys: %w", err)
	}

	for _, k := range keys {
		err := tx.Exec(`UPDATE credentials
SET identifier = ?, hash = ?, revoked = (SELECT revoked FROM pre_auth_keys WHERE id = ?)
WHERE id = ?`, legacyAuthKeyIdentifier(k.Key), hashSecret(k.Key), k.ID, k.ID).Error
		if err != nil {
			return fmt.Errorf("hashing legacy pre-auth key %d: %w", k.ID, err)
		}
	}

	return nil
}

// retargetNodesAuthKeyFK repoints the nodes.auth_key_id foreign key from
// pre_auth_keys(id) to credentials(id). Postgres alters the constraint in place;
// SQLite, which cannot alter a foreign key, rebuilds the table. The rebuild runs
// with foreign keys enabled: no table references nodes, and every auth_key_id
// now points at a credentials row, so no FK toggling is required.
//
// TODO(kradalby): remove in 0.31 with the credentials migration.
func retargetNodesAuthKeyFK(tx *gorm.DB) error {
	if tx.Name() != "sqlite" {
		err := tx.Exec(`ALTER TABLE nodes DROP CONSTRAINT IF EXISTS fk_nodes_auth_key`).Error
		if err != nil {
			return fmt.Errorf("dropping nodes auth_key constraint: %w", err)
		}

		err = tx.Exec(`ALTER TABLE nodes ADD CONSTRAINT fk_nodes_auth_key
FOREIGN KEY (auth_key_id) REFERENCES credentials(id)`).Error
		if err != nil {
			return fmt.Errorf("adding nodes auth_key constraint: %w", err)
		}

		return nil
	}

	// Dropping the table resets its AUTOINCREMENT counter to max(id); carry the
	// old counter over so ids of deleted nodes are never handed out again.
	seq, err := sqliteSequence(tx, "nodes")
	if err != nil {
		return err
	}

	stmts := []string{
		`CREATE TABLE nodes_new(
  id integer PRIMARY KEY AUTOINCREMENT,
  machine_key text,
  node_key text,
  disco_key text,
  endpoints text,
  host_info text,
  ipv4 text,
  ipv6 text,
  hostname text,
  given_name varchar(63),
  user_id integer,
  register_method text,
  tags text,
  auth_key_id integer,
  last_seen datetime,
  expiry datetime,
  approved_routes text,

  created_at datetime,
  updated_at datetime,
  deleted_at datetime,

  CONSTRAINT fk_nodes_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_nodes_auth_key FOREIGN KEY(auth_key_id) REFERENCES credentials(id)
)`,
		`INSERT INTO nodes_new
  (id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, tags, auth_key_id, last_seen, expiry, approved_routes, created_at, updated_at, deleted_at)
SELECT id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, tags, auth_key_id, last_seen, expiry, approved_routes, created_at, updated_at, deleted_at
FROM nodes`,
		`DROP TABLE nodes`,
		`ALTER TABLE nodes_new RENAME TO nodes`,
	}

	for _, stmt := range stmts {
		err := tx.Exec(stmt).Error
		if err != nil {
			return fmt.Errorf("rebuilding nodes table: %w", err)
		}
	}

	return raiseSQLiteSequence(tx, "nodes", seq)
}

// continuePreAuthKeySequence advances the credentials id sequence to at least
// the last id pre_auth_keys ever allocated.
//
// TODO(kradalby): remove in 0.31 with the credentials migration.
func continuePreAuthKeySequence(tx *gorm.DB) error {
	if tx.Name() == "sqlite" {
		seq, err := sqliteSequence(tx, "pre_auth_keys")
		if err != nil {
			return err
		}

		return raiseSQLiteSequence(tx, "credentials", seq)
	}

	var last int64

	// pg_sequences.last_value is NULL for a sequence that was never used.
	err := tx.Raw(`SELECT COALESCE(MAX(last_value), 0) FROM pg_sequences
WHERE schemaname = current_schema()
  AND sequencename = (SELECT relname FROM pg_class WHERE oid = pg_get_serial_sequence('pre_auth_keys', 'id')::regclass)`).
		Scan(&last).Error
	if err != nil {
		return fmt.Errorf("reading pre_auth_keys id sequence: %w", err)
	}

	err = tx.Exec(`SELECT setval(pg_get_serial_sequence('credentials','id'),
GREATEST((SELECT COALESCE(MAX(id), 0) FROM credentials), ?, 1))`, last).Error
	if err != nil {
		return fmt.Errorf("advancing credentials id sequence: %w", err)
	}

	return nil
}

// sqliteSequence returns the AUTOINCREMENT counter of table, 0 if unset.
//
// TODO(kradalby): remove in 0.31 with the credentials migration.
func sqliteSequence(tx *gorm.DB, table string) (int64, error) {
	var seq int64

	err := tx.Raw(`SELECT COALESCE(MAX(seq), 0) FROM sqlite_sequence WHERE name = ?`, table).
		Scan(&seq).Error
	if err != nil {
		return 0, fmt.Errorf("reading %s sequence: %w", table, err)
	}

	return seq, nil
}

// raiseSQLiteSequence sets the AUTOINCREMENT counter of table to at least seq.
//
// TODO(kradalby): remove in 0.31 with the credentials migration.
func raiseSQLiteSequence(tx *gorm.DB, table string, seq int64) error {
	res := tx.Exec(`UPDATE sqlite_sequence SET seq = MAX(seq, ?) WHERE name = ?`, seq, table)
	if res.Error == nil && res.RowsAffected == 0 && seq > 0 {
		// No row yet: nothing has been inserted into table.
		res = tx.Exec(`INSERT INTO sqlite_sequence(name, seq) VALUES(?, ?)`, table, seq)
	}

	if res.Error != nil {
		return fmt.Errorf("restoring %s sequence: %w", table, res.Error)
	}

	return nil
}
