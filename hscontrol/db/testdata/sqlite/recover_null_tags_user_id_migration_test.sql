-- Test SQL dump for the null-tags user_id RECOVERY migration.
--
-- Represents a database that already upgraded to 0.29.0, where the buggy
-- clear-tagged-node-user-id migration (202602201200) already cleared
-- user_id on untagged nodes whose tags column held 'null'. The recovery
-- migration runs against this state and re-derives user_id from the node's
-- pre-auth key where possible.
-- Fixes: https://github.com/juanfont/headscale/issues/3323

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

-- Migrations table: everything through the current last migration has been
-- applied (this DB already ran the buggy clear-tagged migration). The new
-- recovery migration is intentionally absent so it runs against this dump.
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
INSERT INTO migrations VALUES('202605221435-clear-zero-time-node-expiry');

-- Users table
CREATE TABLE `users` (`id` integer PRIMARY KEY AUTOINCREMENT,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`name` text,`display_name` text,`email` text,`provider_identifier` text,`provider` text,`profile_pic_url` text);
INSERT INTO users VALUES(1,'2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL,'user1','User One','user1@example.com',NULL,NULL,NULL);
INSERT INTO users VALUES(2,'2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL,'user2','User Two','user2@example.com',NULL,NULL,NULL);

-- Pre-auth keys table. Key 1 belongs to user2, key 2 to user1.
CREATE TABLE `pre_auth_keys` (`id` integer PRIMARY KEY AUTOINCREMENT,`key` text,`user_id` integer,`reusable` numeric,`ephemeral` numeric DEFAULT false,`used` numeric DEFAULT false,`tags` text,`created_at` datetime,`expiration` datetime,`prefix` text,`hash` blob,CONSTRAINT `fk_pre_auth_keys_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL);
INSERT INTO pre_auth_keys VALUES(1,NULL,2,1,false,true,NULL,'2024-01-01 00:00:00+00:00',NULL,'pak1',NULL);
INSERT INTO pre_auth_keys VALUES(2,NULL,1,1,false,true,NULL,'2024-01-01 00:00:00+00:00',NULL,'pak2',NULL);

-- API keys table
CREATE TABLE `api_keys` (`id` integer PRIMARY KEY AUTOINCREMENT,`prefix` text,`hash` blob,`created_at` datetime,`expiration` datetime,`last_seen` datetime);

-- Nodes table
CREATE TABLE IF NOT EXISTS "nodes" (`id` integer PRIMARY KEY AUTOINCREMENT,`machine_key` text,`node_key` text,`disco_key` text,`endpoints` text,`host_info` text,`ipv4` text,`ipv6` text,`hostname` text,`given_name` varchar(63),`user_id` integer,`register_method` text,`tags` text,`auth_key_id` integer,`last_seen` datetime,`expiry` datetime,`approved_routes` text,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,CONSTRAINT `fk_nodes_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,CONSTRAINT `fk_nodes_auth_key` FOREIGN KEY (`auth_key_id`) REFERENCES `pre_auth_keys`(`id`));

-- Node 1: authkey-registered, tags='null', already orphaned (user_id NULL) by
-- the buggy migration. auth_key_id=1 (user2). Recovery: user_id -> 2.
INSERT INTO nodes VALUES(1,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e01','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605501','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57701','[]','{}','100.64.0.1','fd7a:115c:a1e0::1','node1','node1',NULL,'authkey','null',1,'2024-01-01 00:00:00+00:00',NULL,'[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 2: genuinely tagged, user_id correctly cleared. Must stay NULL.
INSERT INTO nodes VALUES(2,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e02','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605502','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57702','[]','{}','100.64.0.2','fd7a:115c:a1e0::2','node2','node2',NULL,'authkey','["tag:server"]',2,'2024-01-01 00:00:00+00:00',NULL,'[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 3: CLI-registered, tags='null', orphaned, no auth_key_id.
-- Unrecoverable: must stay NULL.
INSERT INTO nodes VALUES(3,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e03','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605503','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57703','[]','{}','100.64.0.3','fd7a:115c:a1e0::3','node3','node3',NULL,'cli','null',NULL,'2024-01-01 00:00:00+00:00',NULL,'[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 4: authkey-registered, untouched (user_id still set). Must stay user1.
INSERT INTO nodes VALUES(4,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e04','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605504','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57704','[]','{}','100.64.0.4','fd7a:115c:a1e0::4','node4','node4',1,'authkey','null',2,'2024-01-01 00:00:00+00:00',NULL,'[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Policies table (empty)
CREATE TABLE `policies` (`id` integer PRIMARY KEY AUTOINCREMENT,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`data` text);

DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',2);
INSERT INTO sqlite_sequence VALUES('pre_auth_keys',2);
INSERT INTO sqlite_sequence VALUES('nodes',4);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX idx_policies_deleted_at ON policies(deleted_at);
CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL;
CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier);
CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != '';

COMMIT;
