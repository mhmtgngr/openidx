#!/bin/bash
# Initialize the two PAM-broker Guacamole databases in the dedicated
# pam-guac-postgres instance: guac_direct (direct broker) and guac_ziti (OpenZiti
# broker). Each gets the standard Guacamole JDBC schema loaded. Runs once, on a
# fresh data volume (docker-entrypoint-initdb.d).
#
# Kept separate from init-guacamole.sh (which seeds the shared BrowZer stack's
# `guacamole` DB in the MAIN postgres) so the PAM brokers are fully isolated.

set -e

echo "Initializing PAM-broker Guacamole databases..."

for DB in guac_direct guac_ziti; do
    echo "  creating database ${DB}..."
    psql -v ON_ERROR_STOP=0 --username "$POSTGRES_USER" <<-EOSQL
        CREATE DATABASE ${DB} OWNER $POSTGRES_USER;
EOSQL
    echo "  applying Guacamole schema to ${DB}..."
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "${DB}" \
        < /docker-entrypoint-initdb.d/guacamole-schema.sql
done

echo "PAM-broker Guacamole databases initialized successfully."
