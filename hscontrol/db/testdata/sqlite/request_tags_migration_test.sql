-- Test SQL dump for RequestTags migration (202601121700-migrate-hostinfo-request-tags)
-- and forced_tags->tags rename migration (202511131445-node-forced-tags-to-tags)
--
-- This dump simulates a 0.27.x database where:
-- - Tags from --advertise-tags were stored only in host_info.RequestTags
-- - The tags column is still named forced_tags
--
-- Test scenarios:
-- 1. Node with RequestTags that user is authorized for (should be migrated)
-- 2. Node with RequestTags that user is NOT authorized for (should be rejected)
-- 3. Node with existing forced_tags that should be preserved
-- 4. Node with RequestTags that overlap with existing tags (no duplicates)
-- 5. Node without RequestTags (should be unchanged)
-- 6. Node with RequestTags via group membership (should be migrated)

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

-- Migrations table - includes all migrations BEFORE the two tag migrations
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
-- Note: 202511131445-node-forced-tags-to-tags is NOT included - it will run
-- Note: 202601121700-migrate-hostinfo-request-tags is NOT included - it will run

-- Users table
-- Note: User names must match the usernames in the policy (with @)
CREATE TABLE `users` (`id` integer PRIMARY KEY AUTOINCREMENT,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`name` text,`display_name` text,`email` text,`provider_identifier` text,`provider` text,`profile_pic_url` text);
INSERT INTO users VALUES(1,'2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL,'user1@example.com','User One','user1@example.com',NULL,NULL,NULL);
INSERT INTO users VALUES(2,'2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL,'user2@example.com','User Two','user2@example.com',NULL,NULL,NULL);
INSERT INTO users VALUES(3,'2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL,'admin1@example.com','Admin One','admin1@example.com',NULL,NULL,NULL);

-- Pre-auth keys table
CREATE TABLE `pre_auth_keys` (`id` integer PRIMARY KEY AUTOINCREMENT,`key` text,`user_id` integer,`reusable` numeric,`ephemeral` numeric DEFAULT false,`used` numeric DEFAULT false,`tags` text,`created_at` datetime,`expiration` datetime,`prefix` text,`hash` blob,CONSTRAINT `fk_pre_auth_keys_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL);

-- API keys table
CREATE TABLE `api_keys` (`id` integer PRIMARY KEY AUTOINCREMENT,`prefix` text,`hash` blob,`created_at` datetime,`expiration` datetime,`last_seen` datetime);

-- Nodes table - using OLD schema with forced_tags (not tags)
CREATE TABLE IF NOT EXISTS "nodes" (`id` integer PRIMARY KEY AUTOINCREMENT,`machine_key` text,`node_key` text,`disco_key` text,`endpoints` text,`host_info` text,`ipv4` text,`ipv6` text,`hostname` text,`given_name` varchar(63),`user_id` integer,`register_method` text,`forced_tags` text,`auth_key_id` integer,`expiry` datetime,`last_seen` datetime,`approved_routes` text,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,CONSTRAINT `fk_nodes_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,CONSTRAINT `fk_nodes_auth_key` FOREIGN KEY (`auth_key_id`) REFERENCES `pre_auth_keys`(`id`));

-- Node 1: user1 owns it, has RequestTags for tag:server (user1 is authorized for this tag)
-- Expected: tag:server should be added to tags
INSERT INTO nodes VALUES(1,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e01','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605501','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57701','[]','{"RequestTags":["tag:server"]}','100.64.0.1','fd7a:115c:a1e0::1','node1','node1',1,'oidc','[]',NULL,'0001-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 2: user1 owns it, has RequestTags for tag:unauthorized (user1 is NOT authorized for this tag)
-- Expected: tag:unauthorized should be rejected, tags stays empty
INSERT INTO nodes VALUES(2,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e02','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605502','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57702','[]','{"RequestTags":["tag:unauthorized"]}','100.64.0.2','fd7a:115c:a1e0::2','node2','node2',1,'oidc','[]',NULL,'0001-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 3: user2 owns it, has RequestTags for tag:client (user2 is authorized)
-- Also has existing forced_tags that should be preserved
-- Expected: tag:client added, tag:existing preserved
INSERT INTO nodes VALUES(3,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e03','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605503','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57703','[]','{"RequestTags":["tag:client"]}','100.64.0.3','fd7a:115c:a1e0::3','node3','node3',2,'oidc','["tag:existing"]',NULL,'0001-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 4: user1 owns it, has RequestTags for tag:server which already exists in forced_tags
-- Expected: no duplicates, tags should be ["tag:server"]
INSERT INTO nodes VALUES(4,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e04','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605504','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57704','[]','{"RequestTags":["tag:server"]}','100.64.0.4','fd7a:115c:a1e0::4','node4','node4',1,'oidc','["tag:server"]',NULL,'0001-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 5: user2 owns it, no RequestTags in host_info
-- Expected: tags unchanged (empty)
INSERT INTO nodes VALUES(5,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e05','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605505','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57705','[]','{}','100.64.0.5','fd7a:115c:a1e0::5','node5','node5',2,'oidc','[]',NULL,'0001-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 6: admin1 owns it, has RequestTags for tag:admin (admin1 is in group:admins which owns tag:admin)
-- Expected: tag:admin should be added via group membership
INSERT INTO nodes VALUES(6,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e06','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605506','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57706','[]','{"RequestTags":["tag:admin"]}','100.64.0.6','fd7a:115c:a1e0::6','node6','node6',3,'oidc','[]',NULL,'0001-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Node 7: user1 owns it, has multiple RequestTags (tag:server authorized, tag:forbidden not authorized)
-- Expected: tag:server added, tag:forbidden rejected
INSERT INTO nodes VALUES(7,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e07','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605507','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57707','[]','{"RequestTags":["tag:server","tag:forbidden"]}','100.64.0.7','fd7a:115c:a1e0::7','node7','node7',1,'oidc','[]',NULL,'0001-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00','[]','2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL);

-- Policies table with tagOwners defining who can use which tags
-- Note: Usernames in policy must contain @ (e.g., user1@example.com or just user1@)
CREATE TABLE `policies` (`id` integer PRIMARY KEY AUTOINCREMENT,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`data` text);
INSERT INTO policies VALUES(1,'2024-01-01 00:00:00+00:00','2024-01-01 00:00:00+00:00',NULL,'{
  "groups": {
    "group:admins": ["admin1@example.com"]
  },
  "tagOwners": {
    "tag:server": ["user1@example.com"],
    "tag:client": ["user1@example.com", "user2@example.com"],
    "tag:admin": ["group:admins"]
  },
  "acls": [
    {"action": "accept", "src": ["*"], "dst": ["*:*"]}
  ]
}');

-- Indexes (using exact format expected by schema validation)
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',3);
INSERT INTO sqlite_sequence VALUES('nodes',7);
INSERT INTO sqlite_sequence VALUES('policies',1);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX idx_policies_deleted_at ON policies(deleted_at);
CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL;
CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier);
CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != '';

COMMIT;
