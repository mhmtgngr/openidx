// Migration v100 — Add HRIS connectors table for inbound provisioning.
package migrations

import (
	"time"
)

var migration100 = &Migration{
	Version: 100,
	Name:    "HRIS connectors table",
	Description: "Adds a table to store configuration for inbound HRIS connectors",
	UpSQL:   `CREATE TABLE IF NOT EXISTS hris_connectors (
		id VARCHAR(255) PRIMARY KEY,
		type VARCHAR(50) NOT NULL,
		config JSONB NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT true,
		sync_interval INTEGER NOT NULL DEFAULT 3600,
		last_sync BIGINT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);`,
	DownSQL: `DROP TABLE IF EXISTS hris_connectors;`,
}

func init() {
	registerMigration(migration100)
}
