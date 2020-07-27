#!/bin/bash
cd /build/headscale
echo 'Writing config...'
echo '''
{
    "server_url": "$SERVER_URL",
    "listen_addr": "0.0.0.0:8000",
    "private_key_path": "private.key",
    "public_key_path": "public.key",
    "db_host": "localhost",
    "db_port": 5432,
    "db_name": "headscale",
    "db_user": "admin",
    "db_pass": "$POSTGRES_PASSWORD"
}
''' > config.json

# Wait until PostgreSQL started and listens on port 5432.
while [ -z "`netstat -tln | grep 5432`" ]; do
  echo 'Waiting for PostgreSQL to start ...'
  sleep 1
done
echo 'PostgreSQL started.'

# Start server.
echo 'Starting server...'

./headscale