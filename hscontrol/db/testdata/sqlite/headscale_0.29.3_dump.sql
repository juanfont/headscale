-- Database created by a real headscale v0.29.3 binary (go build of tag
-- v0.29.3): `headscale serve` ran the migrations and wrote
-- database_versions; users, the API key and the bcrypt pre-auth keys were
-- created with the v0.29.3 CLI. The legacy plaintext pre-auth key and all
-- nodes were inserted by SQL against that schema; node 6 was inserted then
-- deleted so sqlite_sequence(nodes) > max(nodes.id). Dumped with `.dump`.
--
-- Users: 1=alice, 2=bob
-- API key (id 1):
--   hskey-api-ZRVzG0vKkUb4-dqem7jxt7Aun0JqfZpbsvrBDYdQV-RK8S9qbiAAniiuTxIj73LeDUDukVYJBqmDh
-- Pre-auth keys:
--   1 reusable, alice:
--     hskey-auth-H3XVw1W-6s4J-KTmfCUFG_4gJ8CuI5j3W67DX8eMnQJi6W8ToVK0esXMrPK5YTm_p8THq6VnH22-K
--   2 single-use, alice, used=true:
--     hskey-auth-wVBSRrOq9_aQ-hg9vYfijlQDPFKx6lvJ4sT4376N6OV5IijEEQzRouXpgMENeWaozgPsjhepjSkxf
--   3 ephemeral, bob:
--     hskey-auth-nBq0Csj0PIiH-qNvobKcN8PeuvzS8985BnYYxIdVhh9D6vnRaTUuochTgZyQrA8ius5yuVzD9WZLA
--   4 tagged tag:server, no user:
--     hskey-auth-q3rudWOszD6G-Oy9BLGYYpGg-HdXjlwXQT8-9IfrcQ2aIdJfzhddkxQoSgN0JkdVEUxXboxS55mrH
--   5 legacy plaintext, bob, reusable, ephemeral:
--     plaintextlegacykey0000000000000000000000000000
-- Nodes (id -> auth_key_id): 1->1, 2->2, 3->3, 4->4 (tagged), 5->5 (ephemeral)
-- sqlite_sequence nodes=6; database_versions version='v0.29.3'

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE `database_versions` (`id` integer PRIMARY KEY AUTOINCREMENT,`version` text NOT NULL,`updated_at` datetime);
INSERT INTO database_versions VALUES(1,'v0.29.3','2026-09-23 15:28:31.661895503+00:00');
CREATE TABLE `migrations` (`id` text,PRIMARY KEY (`id`));
INSERT INTO migrations VALUES('SCHEMA_INIT');
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
INSERT INTO migrations VALUES('202606181200-recover-null-tags-node-user-id');
INSERT INTO migrations VALUES('202607241200-clear-tagged-node-expiry');
CREATE TABLE `users` (`id` integer PRIMARY KEY AUTOINCREMENT,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`name` text,`display_name` text,`email` text,`provider_identifier` text,`provider` text,`profile_pic_url` text);
INSERT INTO users VALUES(1,'2026-09-23 15:28:36.088806516+00:00','2026-09-23 15:28:36.088806516+00:00',NULL,'alice','','',NULL,'','');
INSERT INTO users VALUES(2,'2026-09-23 15:28:36.136634424+00:00','2026-09-23 15:28:36.136634424+00:00',NULL,'bob','','',NULL,'','');
CREATE TABLE `pre_auth_keys` (`id` integer PRIMARY KEY AUTOINCREMENT,`key` text,`prefix` text,`hash` blob,`user_id` integer,`reusable` numeric,`ephemeral` numeric DEFAULT false,`used` numeric DEFAULT false,`tags` text,`created_at` datetime,`expiration` datetime,CONSTRAINT `fk_pre_auth_keys_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL);
INSERT INTO pre_auth_keys VALUES(1,'','H3XVw1W-6s4J',x'243261243130244b3171432f416e3347537a31684f644c4f6b575468754d69386a4f59724235367356787378707a684e705a41776e77395551517232',1,1,0,0,'[]','2026-09-23 15:28:40.293817627+00:00','2036-09-20 15:28:40.293282175+00:00');
INSERT INTO pre_auth_keys VALUES(2,'','wVBSRrOq9_aQ',x'243261243130244330316e45364e70736e504d3247467344546573682e394a56317149424d654a494944616450322e4f6e374e53556b79563341752e',1,0,0,1,'[]','2026-09-23 15:28:40.382033566+00:00','2036-09-20 15:28:40.381476756+00:00');
INSERT INTO pre_auth_keys VALUES(3,'','nBq0Csj0PIiH',x'24326124313024387338686568495a4e4d6676424b6d76714c686a417573544933674375482e68716b323377734f63593349643832532f70765a6a79',2,0,1,0,'[]','2026-09-23 15:28:40.470602839+00:00','2036-09-20 15:28:40.47008079+00:00');
INSERT INTO pre_auth_keys VALUES(4,'','q3rudWOszD6G',x'24326124313024674f38324c4c7632775245357973636c2f6357397965315834794869534d632f4757396a7a4755447078314b715162725468632e6d',NULL,0,0,0,'["tag:server"]','2026-09-23 15:28:40.55735853+00:00','2036-09-20 15:28:40.556981794+00:00');
INSERT INTO pre_auth_keys VALUES(5,'plaintextlegacykey0000000000000000000000000000',NULL,NULL,2,1,1,0,'[]','2026-09-23 15:29:00.000000000+00:00','2036-09-20 15:29:00.000000000+00:00');
CREATE TABLE `api_keys` (`id` integer PRIMARY KEY AUTOINCREMENT,`prefix` text,`hash` blob,`created_at` datetime,`expiration` datetime,`last_seen` datetime);
INSERT INTO api_keys VALUES(1,'ZRVzG0vKkUb4',x'24326124313024476c5333616f33647a63716531472e4649593263594f52567447796d65316b2e7a445136495a576a324a6357493465306b57593832','2026-09-23 15:28:40.276116989+00:00','2036-09-20 15:28:40.206224138+00:00',NULL);
CREATE TABLE `nodes` (`id` integer PRIMARY KEY AUTOINCREMENT,`machine_key` text,`node_key` text,`disco_key` text,`endpoints` text,`host_info` text,`ipv4` text,`ipv6` text,`hostname` text,`given_name` varchar(63),`user_id` integer,`register_method` text,`tags` text,`auth_key_id` integer,`expiry` datetime,`last_seen` datetime,`approved_routes` text,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,CONSTRAINT `fk_nodes_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,CONSTRAINT `fk_nodes_auth_key` FOREIGN KEY (`auth_key_id`) REFERENCES `pre_auth_keys`(`id`));
INSERT INTO nodes VALUES(1,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e01','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605501','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57701','[]','{}','100.64.0.1','fd7a:115c:a1e0::1','node1','node1',1,'authkey','[]',1,NULL,'2026-09-23 15:30:01.000000000+00:00','[]','2026-09-23 15:30:01.000000000+00:00','2026-09-23 15:30:01.000000000+00:00',NULL);
INSERT INTO nodes VALUES(2,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e02','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605502','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57702','[]','{}','100.64.0.2','fd7a:115c:a1e0::2','node2','node2',1,'authkey','[]',2,NULL,'2026-09-23 15:30:02.000000000+00:00','[]','2026-09-23 15:30:02.000000000+00:00','2026-09-23 15:30:02.000000000+00:00',NULL);
INSERT INTO nodes VALUES(3,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e03','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605503','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57703','[]','{}','100.64.0.3','fd7a:115c:a1e0::3','node3','node3',2,'authkey','[]',3,NULL,'2026-09-23 15:30:03.000000000+00:00','[]','2026-09-23 15:30:03.000000000+00:00','2026-09-23 15:30:03.000000000+00:00',NULL);
INSERT INTO nodes VALUES(4,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e04','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605504','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57704','[]','{}','100.64.0.4','fd7a:115c:a1e0::4','node4','node4',NULL,'authkey','["tag:server"]',4,NULL,'2026-09-23 15:30:04.000000000+00:00','[]','2026-09-23 15:30:04.000000000+00:00','2026-09-23 15:30:04.000000000+00:00',NULL);
INSERT INTO nodes VALUES(5,'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e05','nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c1605505','discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf57705','[]','{}','100.64.0.5','fd7a:115c:a1e0::5','node5','node5',2,'authkey','[]',5,NULL,'2026-09-23 15:30:05.000000000+00:00','[]','2026-09-23 15:30:05.000000000+00:00','2026-09-23 15:30:05.000000000+00:00',NULL);
CREATE TABLE `policies` (`id` integer PRIMARY KEY AUTOINCREMENT,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`data` text);
PRAGMA writable_schema=ON;
CREATE TABLE IF NOT EXISTS sqlite_sequence(name,seq);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('database_versions',1);
INSERT INTO sqlite_sequence VALUES('users',2);
INSERT INTO sqlite_sequence VALUES('api_keys',1);
INSERT INTO sqlite_sequence VALUES('pre_auth_keys',5);
INSERT INTO sqlite_sequence VALUES('nodes',6);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX idx_policies_deleted_at ON policies(deleted_at);
CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL;
CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier);
CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL;
CREATE UNIQUE INDEX idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != '';
PRAGMA writable_schema=OFF;
COMMIT;
