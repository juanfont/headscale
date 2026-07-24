-- Test SQL dump for the clear-tagged-node-expiry migration
-- (202607241200-clear-tagged-node-expiry)
--
-- A buggy handleLogout stamped a past key expiry on tagged nodes. Tagged
-- nodes are owned by their tags and never expire (KB 1068), so such a row is
-- reported as permanently Expired and can never re-authenticate. The migration
-- clears expiry on tagged rows while leaving user-owned nodes untouched.
-- Fixes: https://github.com/juanfont/headscale/issues/3371

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

-- Migrations table: entries applied up to (but not including) the fix. The
-- intervening expiry migrations (clear-zero-time) also run against this dump;
-- their predicates (expiry < 1900) do not match the post-2000 dates below, so
-- they leave these rows for the new migration to handle.
CREATE TABLE `migrations` (`id` text,PRIMARY KEY (`id`));
INSERT INTO migrations VALUES('202312101416');
INSERT INTO migrations VALUES('202312101430');
INSERT INTO migrations VALUES('202402151347');
INSERT INTO migrations VALUES('2024041121742');
INSERT INTO migrations VALUES('202406021630');
INSERT INTO migrations VALUES('202409271400');
INSERT INTO migrations VALUES('202407191627');
INSERT INTO migrations VALUES('202408181235');
INSERT INTO migrations VALUES('202501221827');
INSERT INTO migrations VALUES('202501311657');
INSERT INTO migrations VALUES('202502070949');
INSERT INTO migrations VALUES('202502131714');
INSERT INTO migrations VALUES('202502171819');
INSERT INTO migrations VALUES('202505091439');
INSERT INTO migrations VALUES('202505141324');
INSERT INTO migrations VALUES('202507021200');
INSERT INTO migrations VALUES('202510311551');
INSERT INTO migrations VALUES('202511101554-drop-old-idx');
INSERT INTO migrations VALUES('202511011637-preauthkey-bcrypt');
INSERT INTO migrations VALUES('202511122344-remove-newline-index');
INSERT INTO migrations VALUES('202511131445-node-forced-tags-to-tags');
INSERT INTO migrations VALUES('202601121700-migrate-hostinfo-request-tags');
INSERT INTO migrations VALUES('202602201200-clear-tagged-node-user-id');

-- Users table
CREATE TABLE `users` (`id` integer PRIMARY KEY AUTOINCREMENT,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`name` text,`display_name` text,`email` text,`provider_identifier` text,`provider` text,`profile_pic_url` text);
INSERT INTO users VALUES(1,'2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL,'user1','User One','user1@example.com',NULL,NULL,NULL);

-- Pre-auth keys table
CREATE TABLE `pre_auth_keys` (`id` integer PRIMARY KEY AUTOINCREMENT,`key` text,`user_id` integer,`reusable` numeric,`ephemeral` numeric DEFAULT false,`used` numeric DEFAULT false,`tags` text,`created_at` datetime,`expiration` datetime,`prefix` text,`hash` blob,CONSTRAINT `fk_pre_auth_keys_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL);

-- API keys table
CREATE TABLE `api_keys` (`id` integer PRIMARY KEY AUTOINCREMENT,`prefix` text,`hash` blob,`created_at` datetime,`expiration` datetime,`last_seen` datetime);

-- Nodes table - current schema (after the tags rename + last_seen/expiry reordering)
CREATE TABLE IF NOT EXISTS "nodes" (`id` integer PRIMARY KEY AUTOINCREMENT,`machine_key` text,`node_key` text,`disco_key` text,`endpoints` text,`host_info` text,`ipv4` text,`ipv6` text,`hostname` text,`given_name` varchar(63),`user_id` integer,`register_method` text,`tags` text,`auth_key_id` integer,`last_seen` datetime,`expiry` datetime,`approved_routes` text,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,CONSTRAINT `fk_nodes_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,CONSTRAINT `fk_nodes_auth_key` FOREIGN KEY (`auth_key_id`) REFERENCES `pre_auth_keys`(`id`));

-- Node 1: TAGGED, user_id NULL, stale PAST expiry (the #3371 bug). After migration: expiry NULL.
INSERT INTO nodes VALUES(1,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e01','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605501','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57701','[]','{}','100.64.0.1','fd7a:115c:a1e0::1','node1','node1',NULL,'authkey','["tag:foo"]',NULL,'2024-01-01 00:00:00+00:00','2020-06-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 2: TAGGED, user_id NULL, FUTURE expiry. Tagged nodes never expire, so cleared to NULL too.
INSERT INTO nodes VALUES(2,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e02','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605502','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57702','[]','{}','100.64.0.2','fd7a:115c:a1e0::2','node2','node2',NULL,'authkey','["tag:foo"]',NULL,'2024-01-01 00:00:00+00:00','2099-01-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 3: TAGGED, user_id NULL, expiry already NULL. After migration: still NULL.
INSERT INTO nodes VALUES(3,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e03','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605503','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57703','[]','{}','100.64.0.3','fd7a:115c:a1e0::3','node3','node3',NULL,'authkey','["tag:foo"]',NULL,'2024-01-01 00:00:00+00:00',NULL,'[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 4: UNTAGGED user-owned (tags='null'), PAST expiry. Must be PRESERVED (guard against
-- the #3323-class over-match: a nil tags slice marshals to the literal 'null').
INSERT INTO nodes VALUES(4,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e04','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605504','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57704','[]','{}','100.64.0.4','fd7a:115c:a1e0::4','node4','node4',1,'cli','null',NULL,'2024-01-01 00:00:00+00:00','2020-06-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 5: UNTAGGED user-owned (tags='[]'), FUTURE expiry. Must be PRESERVED.
INSERT INTO nodes VALUES(5,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e05','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605505','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57705','[]','{}','100.64.0.5','fd7a:115c:a1e0::5','node5','node5',1,'cli','[]',NULL,'2024-01-01 00:00:00+00:00','2099-01-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Policies table (empty)
CREATE TABLE `policies` (`id` integer PRIMARY KEY AUTOINCREMENT,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`data` text);

DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',1);
INSERT INTO sqlite_sequence VALUES('nodes',5);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX idx_policies_deleted_at ON policies(deleted_at);
CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL;
CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier);
CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != '';

COMMIT;
