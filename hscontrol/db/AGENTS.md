# hscontrol/db

## Migrations

Violating these corrupts production databases. Migrations start at 0.29.0;
`checkMinimumMigration` (`versioncheck.go`) refuses older databases.

1. Never reorder or edit committed migrations. Append new ones to the end.
2. Never disable foreign keys.
3. ID format `YYYYMMDDHHMM-short-description`, e.g.
   `202607241200-clear-tagged-node-expiry`.
4. Never `AutoMigrate` in a migration; write explicit DDL.
5. Run multi-statement migrations in `tx.Transaction` so a failure leaves the
   database retryable.

Some races surface only on SQLite or only on PostgreSQL; run integration tests
with `--postgres` too.
