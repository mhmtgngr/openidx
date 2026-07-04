#!/bin/sh
# Sets the openidx_app role password at first cluster init. Mounted as a zz- initdb
# hook so it runs AFTER 00-bootstrap.sql created the (passwordless) role. Only runs
# on first init of a fresh volume; for an existing volume set it once via ALTER ROLE.
set -e
if [ -n "$OPENIDX_APP_PASSWORD" ]; then
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -c "ALTER ROLE openidx_app WITH LOGIN PASSWORD '$OPENIDX_APP_PASSWORD';"
fi
