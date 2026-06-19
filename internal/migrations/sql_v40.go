package migrations

// Migration v40 — access-proxy / App Publish schema reconciliation.
//
// The access service's "App Publish" feature (register an internal app →
// discover paths → publish as authenticated proxy routes) and the routes list
// were broken on managed-RDS/Helm/`migrate` deploys:
//   - GET /api/v1/access/apps → 500: tables published_apps + discovered_paths
//     (and service_features) existed only in deployments/docker/init-db.sql.
//   - GET /api/v1/access/routes → 500 ("column idp_id does not exist"): the Go
//     migration that created proxy_routes drifted from init-db.sql, which had
//     since gained ~12 columns (idp_id, route_type, remote_host/port, posture,
//     risk, guacamole, browzer, …) that the access code SELECTs.
//
// This migration reconciles the schema to match init-db.sql. All statements are
// idempotent (CREATE … IF NOT EXISTS / ADD COLUMN IF NOT EXISTS), so it is a
// no-op on clusters bootstrapped from init-db.sql.
var accessSchemaUp = `-- Migration 040: access-proxy / App Publish tables + proxy_routes column drift.

-- App Publish tables ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS published_apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    target_url VARCHAR(500) NOT NULL,
    spec_url VARCHAR(500),
    status VARCHAR(50) DEFAULT 'pending',
    discovery_started_at TIMESTAMPTZ,
    discovery_completed_at TIMESTAMPTZ,
    discovery_error TEXT,
    discovery_strategies JSONB DEFAULT '[]',
    total_paths_discovered INTEGER DEFAULT 0,
    total_paths_published INTEGER DEFAULT 0,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_published_apps_status ON published_apps(status);

CREATE TABLE IF NOT EXISTS discovered_paths (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES published_apps(id) ON DELETE CASCADE,
    path VARCHAR(500) NOT NULL,
    http_methods JSONB DEFAULT '["GET"]',
    classification VARCHAR(50) NOT NULL,
    classification_source VARCHAR(50) DEFAULT 'auto',
    discovery_strategy VARCHAR(50),
    suggested_policy TEXT,
    require_auth BOOLEAN DEFAULT true,
    allowed_roles JSONB DEFAULT '[]',
    require_device_trust BOOLEAN DEFAULT false,
    published BOOLEAN DEFAULT false,
    route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(app_id, path)
);
CREATE INDEX IF NOT EXISTS idx_discovered_paths_app ON discovered_paths(app_id);
CREATE INDEX IF NOT EXISTS idx_discovered_paths_classification ON discovered_paths(classification);

CREATE TABLE IF NOT EXISTS service_features (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id UUID NOT NULL REFERENCES proxy_routes(id) ON DELETE CASCADE,
    feature_name VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT false,
    config JSONB DEFAULT '{}',
    resource_ids JSONB DEFAULT '{}',
    status VARCHAR(50) DEFAULT 'disabled',
    error_message TEXT,
    last_health_check TIMESTAMPTZ,
    health_status VARCHAR(20) DEFAULT 'unknown',
    enabled_at TIMESTAMPTZ,
    enabled_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(route_id, feature_name)
);
CREATE INDEX IF NOT EXISTS idx_service_features_route ON service_features(route_id);
CREATE INDEX IF NOT EXISTS idx_service_features_feature ON service_features(feature_name);

-- proxy_routes column drift (init-db.sql had these; the migrations lagged) ----
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS idp_id UUID REFERENCES identity_providers(id);
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS route_type VARCHAR(20) DEFAULT 'http';
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS remote_host VARCHAR(255);
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS remote_port INTEGER;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS reverify_interval INTEGER DEFAULT 0;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS posture_check_ids JSONB;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS inline_policy TEXT;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS require_device_trust BOOLEAN DEFAULT false;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS allowed_countries JSONB;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS max_risk_score INTEGER DEFAULT 100;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS guacamole_connection_id VARCHAR(255);
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS browzer_enabled BOOLEAN DEFAULT false;

-- proxy_sessions companion column ---------------------------------------------
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS idp_id UUID;
`

var accessSchemaDown = `-- Migration 040 down.
DROP TABLE IF EXISTS service_features;
DROP TABLE IF EXISTS discovered_paths;
DROP TABLE IF EXISTS published_apps;
ALTER TABLE proxy_routes
    DROP COLUMN IF EXISTS idp_id,
    DROP COLUMN IF EXISTS route_type,
    DROP COLUMN IF EXISTS remote_host,
    DROP COLUMN IF EXISTS remote_port,
    DROP COLUMN IF EXISTS reverify_interval,
    DROP COLUMN IF EXISTS posture_check_ids,
    DROP COLUMN IF EXISTS inline_policy,
    DROP COLUMN IF EXISTS require_device_trust,
    DROP COLUMN IF EXISTS allowed_countries,
    DROP COLUMN IF EXISTS max_risk_score,
    DROP COLUMN IF EXISTS guacamole_connection_id,
    DROP COLUMN IF EXISTS browzer_enabled;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS idp_id;
`
