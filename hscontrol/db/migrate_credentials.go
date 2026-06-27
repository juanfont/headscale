package db

import (
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// migrateToCredentials backfills the unified credentials table from the four
// per-kind tables and drops them. Pre-auth keys are migrated first preserving
// their ids so nodes.auth_key_id stays valid; the nodes FK is then retargeted to
// credentials(id). Runs with foreign keys enabled on SQLite (per runMigrations),
// so the steps are ordered to never leave a dangling reference.
func migrateToCredentials(tx *gorm.DB) error {
	// Clear node references to legacy plaintext pre-auth keys (empty prefix);
	// these are not migrated, so a node pointing at one would dangle.
	err := tx.Exec(`UPDATE nodes SET auth_key_id = NULL
WHERE auth_key_id IN (SELECT id FROM pre_auth_keys WHERE prefix IS NULL OR prefix = '')`).Error
	if err != nil {
		return fmt.Errorf("clearing plaintext auth_key references: %w", err)
	}

	// Pre-auth keys first, preserving ids so nodes.auth_key_id stays valid.
	err = tx.Exec(`INSERT INTO credentials
  (id, kind, identifier, hash, user_id, description, reusable, ephemeral, used, tags, expiration, revoked, created_at)
SELECT id, ?, prefix, hash, user_id, description, reusable, ephemeral, used, tags, expiration, revoked, created_at
FROM pre_auth_keys WHERE prefix IS NOT NULL AND prefix != ''`, types.CredentialPreAuthKey).Error
	if err != nil {
		return fmt.Errorf("backfilling pre-auth keys: %w", err)
	}

	// Postgres does not advance the id sequence on explicit-id inserts; nudge it
	// past the pre-auth ids before the auto-id inserts below. SQLite's
	// AUTOINCREMENT already tracks max(id).
	if tx.Name() != "sqlite" {
		err = tx.Exec(`SELECT setval(pg_get_serial_sequence('credentials','id'),
GREATEST((SELECT COALESCE(MAX(id), 1) FROM credentials), 1))`).Error
		if err != nil {
			return fmt.Errorf("resetting credentials id sequence: %w", err)
		}
	}

	err = tx.Exec(`INSERT INTO credentials (kind, identifier, hash, user_id, last_seen, expiration, created_at)
SELECT ?, prefix, hash, user_id, last_seen, expiration, created_at FROM api_keys`, types.CredentialAPIKey).Error
	if err != nil {
		return fmt.Errorf("backfilling api keys: %w", err)
	}

	err = tx.Exec(`INSERT INTO credentials (kind, identifier, hash, scopes, tags, description, user_id, revoked, created_at)
SELECT ?, client_id, secret_hash, scopes, tags, description, user_id, revoked, created_at FROM oauth_clients`, types.CredentialOAuthClient).Error
	if err != nil {
		return fmt.Errorf("backfilling oauth clients: %w", err)
	}

	err = tx.Exec(`INSERT INTO credentials (kind, identifier, hash, client_id, scopes, tags, expiration, created_at)
SELECT ?, prefix, hash, client_id, scopes, tags, expiration, created_at FROM oauth_access_tokens`, types.CredentialOAuthToken).Error
	if err != nil {
		return fmt.Errorf("backfilling oauth access tokens: %w", err)
	}

	if err := retargetNodesAuthKeyFK(tx); err != nil { //nolint:noinlineerr
		return err
	}

	for _, table := range []string{"pre_auth_keys", "api_keys", "oauth_clients", "oauth_access_tokens"} {
		if err := tx.Migrator().DropTable(table); err != nil { //nolint:noinlineerr
			return fmt.Errorf("dropping %s: %w", table, err)
		}
	}

	return nil
}

// retargetNodesAuthKeyFK repoints the nodes.auth_key_id foreign key from
// pre_auth_keys(id) to credentials(id). Postgres alters the constraint in place;
// SQLite, which cannot alter a foreign key, rebuilds the table. The rebuild runs
// with foreign keys enabled: no table references nodes, and every retained
// auth_key_id now points at a credentials row, so no FK toggling is required.
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
		if err := tx.Exec(stmt).Error; err != nil { //nolint:noinlineerr
			return fmt.Errorf("rebuilding nodes table: %w", err)
		}
	}

	return nil
}
