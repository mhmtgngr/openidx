#!/bin/bash
# Initialize Guacamole database schema
# This script runs during postgres container initialization (docker-entrypoint-initdb.d)

set -e

echo "Initializing Guacamole database..."

# Create the guacamole database if it doesn't exist
psql -v ON_ERROR_STOP=0 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE guacamole OWNER $POSTGRES_USER;
EOSQL

# Apply the Guacamole schema
echo "Applying Guacamole schema..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname guacamole < /docker-entrypoint-initdb.d/guacamole-schema.sql

echo "Guacamole database initialized successfully."
