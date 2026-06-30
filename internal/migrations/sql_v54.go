package migrations

// Migration v54 — reconcile the remaining init-db.sql-only tables into the
// versioned migration set (the broad pass after v38-v45 covered ~15).
//
// 58 tables existed only in deployments/docker/init-db.sql, so managed-Postgres /
// RDS / Helm / migrate installs (which never run init-db.sql) lacked them and
// 500'd across MFA variants, SAML/social/federation, lifecycle, ISPM, audit
// archival, bulk-ops, biometric, passwordless, guacamole and ziti-fabric
// features. DDL is lifted verbatim from init-db.sql, made CREATE TABLE/INDEX IF
// NOT EXISTS, so this is a no-op on docker-compose installs and creates the gap
// elsewhere. Not placed under the v37 RLS belt (consistent with v38-v45); these
// are non-FORCE tables, so the openidx_app role is unaffected. Recurrence is
// guarded by TestInitDBParity.
//
// Note: init-db.sql defines lifecycle_executions twice with incompatible schemas
// (a workflow_id form used by internal/identity and a policy_id form used by
// internal/admin/deprovisioning). The first (workflow_id) wins in init-db, so
// that is what we create here; the dead policy_id index is omitted. The schema
// collision itself is a pre-existing bug tracked separately.
var reconcileTableGapUp = `-- Migration 054: reconcile the 58 init-db.sql-only tables.
CREATE TABLE IF NOT EXISTS ziti_edge_routers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    hostname VARCHAR(255),
    is_online BOOLEAN DEFAULT false,
    is_verified BOOLEAN DEFAULT false,
    role_attributes JSONB DEFAULT '[]',
    os VARCHAR(100),
    arch VARCHAR(100),
    version VARCHAR(100),
    last_seen_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ziti_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_type VARCHAR(100) NOT NULL,
    source VARCHAR(255) NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    labels JSONB DEFAULT '{}',
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ziti_metrics_type ON ziti_metrics(metric_type, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_ziti_metrics_source ON ziti_metrics(source);

CREATE TABLE IF NOT EXISTS ziti_user_sync (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    last_full_sync_at TIMESTAMP WITH TIME ZONE,
    last_auto_sync_at TIMESTAMP WITH TIME ZONE,
    users_synced INTEGER DEFAULT 0,
    users_failed INTEGER DEFAULT 0,
    groups_synced INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'idle',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_geolocation_cache (
    ip_address VARCHAR(45) PRIMARY KEY,
    country_code VARCHAR(10),
    city VARCHAR(255),
    latitude FLOAT,
    longitude FLOAT,
    cached_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS guacamole_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id UUID REFERENCES proxy_routes(id) ON DELETE CASCADE,
    guacamole_connection_id VARCHAR(255) NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    parameters JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(route_id)
);

CREATE INDEX IF NOT EXISTS idx_guacamole_connections_route ON guacamole_connections(route_id);

CREATE TABLE IF NOT EXISTS connection_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id UUID NOT NULL REFERENCES proxy_routes(id) ON DELETE CASCADE,
    test_type VARCHAR(50) NOT NULL,
    success BOOLEAN NOT NULL,
    latency_ms INTEGER,
    error_message TEXT,
    details JSONB DEFAULT '{}',
    tested_at TIMESTAMPTZ DEFAULT NOW(),
    tested_by UUID REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_connection_tests_route ON connection_tests(route_id);

CREATE INDEX IF NOT EXISTS idx_connection_tests_type ON connection_tests(test_type);

CREATE INDEX IF NOT EXISTS idx_connection_tests_tested_at ON connection_tests(tested_at DESC);

CREATE TABLE IF NOT EXISTS unified_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_ip VARCHAR(45),
    details JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_unified_audit_source ON unified_audit_events(source, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_unified_audit_route ON unified_audit_events(route_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_unified_audit_user ON unified_audit_events(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_unified_audit_event_type ON unified_audit_events(event_type);

CREATE INDEX IF NOT EXISTS idx_unified_audit_created ON unified_audit_events(created_at DESC);

CREATE TABLE IF NOT EXISTS guacamole_connection_pool (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id VARCHAR(255) NOT NULL,
    token VARCHAR(500) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ DEFAULT NOW(),
    use_count INTEGER DEFAULT 1,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_guac_pool_connection ON guacamole_connection_pool(connection_id);

CREATE INDEX IF NOT EXISTS idx_guac_pool_user ON guacamole_connection_pool(user_id);

CREATE INDEX IF NOT EXISTS idx_guac_pool_expires ON guacamole_connection_pool(expires_at);

CREATE TABLE IF NOT EXISTS external_audit_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source VARCHAR(50) UNIQUE NOT NULL,
    last_sync_at TIMESTAMPTZ,
    last_event_id VARCHAR(255),
    sync_cursor JSONB DEFAULT '{}',
    error_message TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_sms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    phone_number VARCHAR(20) NOT NULL,
    country_code VARCHAR(5) NOT NULL DEFAULT '+1',
    verified BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS idx_mfa_sms_user_id ON mfa_sms(user_id);

CREATE INDEX IF NOT EXISTS idx_mfa_sms_phone ON mfa_sms(phone_number);

CREATE TABLE IF NOT EXISTS mfa_email_otp (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email_address VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS idx_mfa_email_otp_user_id ON mfa_email_otp(user_id);

CREATE TABLE IF NOT EXISTS mfa_otp_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method VARCHAR(20) NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    status VARCHAR(20) DEFAULT 'pending',
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_mfa_otp_challenges_user_id ON mfa_otp_challenges(user_id);

CREATE INDEX IF NOT EXISTS idx_mfa_otp_challenges_status ON mfa_otp_challenges(status, expires_at);

CREATE TABLE IF NOT EXISTS hardware_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255),
    token_type VARCHAR(50) NOT NULL DEFAULT 'yubikey',
    secret_key VARCHAR(255) NOT NULL,
    counter BIGINT DEFAULT 0,
    manufacturer VARCHAR(100),
    model VARCHAR(100),
    firmware_version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'available',
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMP WITH TIME ZONE,
    assigned_by UUID REFERENCES users(id),
    last_used_at TIMESTAMP WITH TIME ZONE,
    use_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_hardware_tokens_serial ON hardware_tokens(serial_number);

CREATE INDEX IF NOT EXISTS idx_hardware_tokens_assigned ON hardware_tokens(assigned_to);

CREATE INDEX IF NOT EXISTS idx_hardware_tokens_status ON hardware_tokens(status);

CREATE TABLE IF NOT EXISTS hardware_token_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id UUID REFERENCES hardware_tokens(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_token_events_token ON hardware_token_events(token_id);

CREATE INDEX IF NOT EXISTS idx_token_events_user ON hardware_token_events(user_id);

CREATE TABLE IF NOT EXISTS biometric_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    platform_authenticator_preferred BOOLEAN DEFAULT true,
    allow_cross_platform BOOLEAN DEFAULT true,
    require_user_verification BOOLEAN DEFAULT true,
    biometric_only_enabled BOOLEAN DEFAULT false,
    resident_key_required BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS biometric_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    applies_to_groups UUID[],
    applies_to_roles VARCHAR(100)[],
    require_platform_authenticator BOOLEAN DEFAULT false,
    allowed_authenticator_types VARCHAR(50)[] DEFAULT ARRAY['platform', 'cross-platform'],
    min_authenticator_level VARCHAR(50) DEFAULT 'any',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_phone_call (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    phone_number VARCHAR(20) NOT NULL,
    country_code VARCHAR(5) NOT NULL,
    verified BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    voice_language VARCHAR(10) DEFAULT 'en-US',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id)
);

CREATE TABLE IF NOT EXISTS phone_call_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    phone_number VARCHAR(25) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    call_type VARCHAR(20) DEFAULT 'outbound',
    call_sid VARCHAR(100),
    status VARCHAR(20) DEFAULT 'pending',
    attempts INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_phone_challenges_user ON phone_call_challenges(user_id);

CREATE INDEX IF NOT EXISTS idx_phone_challenges_status ON phone_call_challenges(status);

CREATE TABLE IF NOT EXISTS mfa_bypass_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    generated_by UUID REFERENCES users(id) NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    max_uses INTEGER DEFAULT 1,
    use_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active',
    used_at TIMESTAMP WITH TIME ZONE,
    used_from_ip VARCHAR(45),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bypass_codes_user ON mfa_bypass_codes(user_id);

CREATE INDEX IF NOT EXISTS idx_bypass_codes_status ON mfa_bypass_codes(status);

CREATE TABLE IF NOT EXISTS mfa_bypass_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bypass_code_id UUID REFERENCES mfa_bypass_codes(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    performed_by UUID REFERENCES users(id),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bypass_audit_user ON mfa_bypass_audit(user_id);

CREATE TABLE IF NOT EXISTS magic_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    purpose VARCHAR(50) DEFAULT 'login',
    redirect_url TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links(token_hash);

CREATE INDEX IF NOT EXISTS idx_magic_links_user ON magic_links(user_id);

CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links(email);

CREATE TABLE IF NOT EXISTS passwordless_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    webauthn_only BOOLEAN DEFAULT false,
    magic_link_enabled BOOLEAN DEFAULT true,
    qr_login_enabled BOOLEAN DEFAULT true,
    preferred_method VARCHAR(50) DEFAULT 'webauthn',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS temp_access_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    protocol VARCHAR(20) NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc')),
    target_host VARCHAR(255) NOT NULL,
    target_port INTEGER NOT NULL CHECK (target_port > 0 AND target_port <= 65535),
    username VARCHAR(255),
    created_by UUID NOT NULL,
    created_by_email VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_uses INTEGER DEFAULT 0,
    current_uses INTEGER DEFAULT 0,
    allowed_ips TEXT[],
    require_mfa BOOLEAN DEFAULT FALSE,
    notify_on_use BOOLEAN DEFAULT FALSE,
    notify_email VARCHAR(255),
    route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
    guacamole_connection_id VARCHAR(255),
    access_url TEXT,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked', 'used')),
    last_used_at TIMESTAMP WITH TIME ZONE,
    last_used_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_temp_access_token ON temp_access_links(token);

CREATE INDEX IF NOT EXISTS idx_temp_access_status ON temp_access_links(status);

CREATE INDEX IF NOT EXISTS idx_temp_access_expires ON temp_access_links(expires_at);

CREATE INDEX IF NOT EXISTS idx_temp_access_created_by ON temp_access_links(created_by);

CREATE TABLE IF NOT EXISTS temp_access_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id UUID NOT NULL REFERENCES temp_access_links(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_temp_access_usage_link ON temp_access_usage(link_id);

CREATE INDEX IF NOT EXISTS idx_temp_access_usage_time ON temp_access_usage(connected_at);

CREATE TABLE IF NOT EXISTS campaign_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID NOT NULL REFERENCES certification_campaigns(id) ON DELETE CASCADE,
    review_id UUID REFERENCES access_reviews(id),
    status VARCHAR(50) DEFAULT 'in_progress',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    deadline TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    total_items INTEGER DEFAULT 0,
    reviewed_items INTEGER DEFAULT 0,
    auto_revoked_items INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_campaign_runs_campaign ON campaign_runs(campaign_id);

CREATE INDEX IF NOT EXISTS idx_campaign_runs_status ON campaign_runs(status);

CREATE TABLE IF NOT EXISTS lifecycle_workflows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    event_type VARCHAR(50) NOT NULL,
    trigger_type VARCHAR(50) DEFAULT 'manual',
    actions JSONB NOT NULL DEFAULT '[]',
    conditions JSONB DEFAULT '{}',
    require_approval BOOLEAN DEFAULT false,
    approval_policy_id UUID,
    enabled BOOLEAN DEFAULT true,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_workflows_event_type ON lifecycle_workflows(event_type);

CREATE INDEX IF NOT EXISTS idx_lifecycle_workflows_enabled ON lifecycle_workflows(enabled);

CREATE TABLE IF NOT EXISTS lifecycle_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES lifecycle_workflows(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    triggered_by UUID,
    trigger_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    actions_completed JSONB DEFAULT '[]',
    actions_failed JSONB DEFAULT '[]',
    error TEXT,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_executions_workflow ON lifecycle_executions(workflow_id);

CREATE INDEX IF NOT EXISTS idx_lifecycle_executions_user ON lifecycle_executions(user_id);

CREATE INDEX IF NOT EXISTS idx_lifecycle_executions_status ON lifecycle_executions(status);

CREATE TABLE IF NOT EXISTS entitlement_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entitlement_type VARCHAR(50) NOT NULL,
    entitlement_id UUID NOT NULL,
    risk_level VARCHAR(20) DEFAULT 'low',
    owner_id UUID,
    description TEXT,
    tags JSONB DEFAULT '[]',
    review_required BOOLEAN DEFAULT false,
    last_reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(entitlement_type, entitlement_id)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_metadata_type ON entitlement_metadata(entitlement_type);

CREATE INDEX IF NOT EXISTS idx_entitlement_metadata_risk ON entitlement_metadata(risk_level);

CREATE TABLE IF NOT EXISTS admin_delegations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegate_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    delegated_by UUID NOT NULL REFERENCES users(id),
    scope_type VARCHAR(50) NOT NULL,
    scope_id UUID NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]',
    enabled BOOLEAN DEFAULT true,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_delegations_delegate ON admin_delegations(delegate_id);

CREATE INDEX IF NOT EXISTS idx_admin_delegations_scope ON admin_delegations(scope_type, scope_id);

CREATE INDEX IF NOT EXISTS idx_admin_delegations_expires ON admin_delegations(expires_at);

CREATE TABLE IF NOT EXISTS saml_service_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    entity_id VARCHAR(500) UNIQUE NOT NULL,
    acs_url VARCHAR(500) NOT NULL,
    slo_url VARCHAR(500),
    certificate TEXT,
    name_id_format VARCHAR(255) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attribute_mappings JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_saml_sp_entity_id ON saml_service_providers(entity_id);

CREATE TABLE IF NOT EXISTS social_account_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    profile_data JSONB,
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(provider_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_social_links_user ON social_account_links(user_id);

CREATE INDEX IF NOT EXISTS idx_social_links_provider ON social_account_links(provider_id, external_id);

CREATE TABLE IF NOT EXISTS webhook_delivery_stats (
    subscription_id VARCHAR(255) PRIMARY KEY,
    total_deliveries INT DEFAULT 0,
    successful_deliveries INT DEFAULT 0,
    failed_deliveries INT DEFAULT 0,
    avg_response_time_ms INT DEFAULT 0,
    last_delivery_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_risk_baselines (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    typical_login_hours JSONB DEFAULT '[]',
    typical_countries JSONB DEFAULT '[]',
    typical_ips JSONB DEFAULT '[]',
    avg_risk_score FLOAT DEFAULT 0,
    login_count INT DEFAULT 0,
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_usage_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    service VARCHAR(100) NOT NULL,
    status_code INT,
    count INT DEFAULT 1,
    avg_latency_ms FLOAT DEFAULT 0,
    hour TIMESTAMP WITH TIME ZONE NOT NULL,
    UNIQUE(endpoint, method, service, status_code, hour)
);

CREATE INDEX IF NOT EXISTS idx_api_metrics_hour ON api_usage_metrics(hour);

CREATE INDEX IF NOT EXISTS idx_api_metrics_endpoint ON api_usage_metrics(endpoint, hour);

CREATE TABLE IF NOT EXISTS feature_adoption (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feature_name VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    first_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    usage_count INT DEFAULT 1,
    UNIQUE(feature_name, user_id)
);

CREATE INDEX IF NOT EXISTS idx_feature_adoption_feature ON feature_adoption(feature_name);

CREATE TABLE IF NOT EXISTS developer_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value JSONB NOT NULL,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_playground_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    state VARCHAR(255),
    code_verifier VARCHAR(255),
    code_challenge VARCHAR(255),
    redirect_uri VARCHAR(500),
    scopes TEXT[],
    status VARCHAR(50) DEFAULT 'initiated',
    authorization_code VARCHAR(255),
    access_token TEXT,
    id_token TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '30 minutes'
);

CREATE INDEX IF NOT EXISTS idx_playground_user ON oauth_playground_sessions(user_id);

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES users(id),
    actor_email VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(100) NOT NULL,
    target_id VARCHAR(255),
    target_name VARCHAR(255),
    before_state JSONB,
    after_state JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    request_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_actor ON admin_audit_log(actor_id);

CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_log(action);

CREATE INDEX IF NOT EXISTS idx_admin_audit_target ON admin_audit_log(target_type, target_id);

CREATE INDEX IF NOT EXISTS idx_admin_audit_time ON admin_audit_log(created_at DESC);

CREATE TABLE IF NOT EXISTS health_check_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name VARCHAR(100) NOT NULL,
    dependency_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    latency_ms INT,
    details JSONB,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_health_history_service ON health_check_history(service_name, checked_at DESC);

CREATE TABLE IF NOT EXISTS error_catalog (
    code VARCHAR(100) PRIMARY KEY,
    http_status INT NOT NULL,
    category VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    resolution_hint TEXT,
    documentation_url VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ispm_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    check_type VARCHAR(100) NOT NULL UNIQUE,
    enabled BOOLEAN DEFAULT true,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    thresholds JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ispm_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES ispm_rules(id) ON DELETE SET NULL,
    check_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    affected_entity_type VARCHAR(100),
    affected_entity_id VARCHAR(255),
    affected_entity_name VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    remediation_action VARCHAR(100),
    remediation_details JSONB DEFAULT '{}',
    dismissed_by UUID REFERENCES users(id),
    dismissed_reason TEXT,
    remediated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ispm_findings_status ON ispm_findings(status);

CREATE INDEX IF NOT EXISTS idx_ispm_findings_severity ON ispm_findings(severity);

CREATE INDEX IF NOT EXISTS idx_ispm_findings_category ON ispm_findings(category);

CREATE INDEX IF NOT EXISTS idx_ispm_findings_entity ON ispm_findings(affected_entity_type, affected_entity_id);

CREATE INDEX IF NOT EXISTS idx_ispm_findings_created ON ispm_findings(created_at DESC);

CREATE TABLE IF NOT EXISTS ispm_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    overall_score INT NOT NULL,
    category_scores JSONB NOT NULL DEFAULT '{}',
    total_findings INT DEFAULT 0,
    critical_findings INT DEFAULT 0,
    high_findings INT DEFAULT 0,
    medium_findings INT DEFAULT 0,
    low_findings INT DEFAULT 0,
    snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ispm_scores_date ON ispm_scores(snapshot_date);

CREATE TABLE IF NOT EXISTS bulk_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    total_items INTEGER DEFAULT 0,
    processed_items INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    errors JSONB DEFAULT '[]',
    parameters JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_bulk_operations_status ON bulk_operations(status);

CREATE INDEX IF NOT EXISTS idx_bulk_operations_created ON bulk_operations(created_at DESC);

CREATE TABLE IF NOT EXISTS bulk_operation_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id UUID NOT NULL REFERENCES bulk_operations(id) ON DELETE CASCADE,
    entity_id UUID,
    entity_name VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    error_message TEXT,
    processed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_bulk_op_items_operation ON bulk_operation_items(operation_id);

CREATE TABLE IF NOT EXISTS email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    subject VARCHAR(500) NOT NULL,
    html_body TEXT NOT NULL,
    text_body TEXT,
    category VARCHAR(100) DEFAULT 'general',
    variables JSONB DEFAULT '[]',
    enabled BOOLEAN DEFAULT true,
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_branding (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    logo_url VARCHAR(500),
    primary_color VARCHAR(20) DEFAULT '#1e40af',
    accent_color VARCHAR(20) DEFAULT '#3b82f6',
    header_text VARCHAR(255),
    footer_text TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(org_id)
);

CREATE TABLE IF NOT EXISTS lifecycle_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    policy_type VARCHAR(50) NOT NULL,
    conditions JSONB DEFAULT '{}',
    actions JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT false,
    schedule VARCHAR(100),
    grace_period_days INTEGER DEFAULT 7,
    notify_before_days INTEGER DEFAULT 3,
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attestation_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    campaign_type VARCHAR(50) NOT NULL,
    scope JSONB DEFAULT '{}',
    reviewer_strategy VARCHAR(50) DEFAULT 'manager',
    status VARCHAR(50) DEFAULT 'draft',
    due_date TIMESTAMP WITH TIME ZONE,
    reminder_days JSONB DEFAULT '[7, 3, 1]',
    escalation_after_days INTEGER DEFAULT 14,
    auto_revoke_on_expiry BOOLEAN DEFAULT false,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_attestation_campaigns_status ON attestation_campaigns(status);

CREATE TABLE IF NOT EXISTS attestation_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID NOT NULL REFERENCES attestation_campaigns(id) ON DELETE CASCADE,
    reviewer_id UUID REFERENCES users(id),
    user_id UUID REFERENCES users(id),
    resource_type VARCHAR(100),
    resource_id UUID,
    resource_name VARCHAR(255),
    decision VARCHAR(50) DEFAULT 'pending',
    delegated_to UUID REFERENCES users(id),
    delegated_at TIMESTAMP WITH TIME ZONE,
    comments TEXT,
    decided_at TIMESTAMP WITH TIME ZONE,
    reminded_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attestation_items_campaign ON attestation_items(campaign_id);

CREATE INDEX IF NOT EXISTS idx_attestation_items_reviewer ON attestation_items(reviewer_id, decision);

CREATE TABLE IF NOT EXISTS audit_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    event_category VARCHAR(100) DEFAULT 'all',
    retention_days INTEGER NOT NULL,
    archive_enabled BOOLEAN DEFAULT true,
    archive_format VARCHAR(50) DEFAULT 'json_gz',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_archives (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    date_range_start TIMESTAMP WITH TIME ZONE,
    date_range_end TIMESTAMP WITH TIME ZONE,
    event_count INTEGER DEFAULT 0,
    file_size BIGINT DEFAULT 0,
    file_path VARCHAR(500),
    format VARCHAR(50) DEFAULT 'json_gz',
    status VARCHAR(50) DEFAULT 'creating',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_archives_status ON audit_archives(status);

CREATE INDEX IF NOT EXISTS idx_audit_archives_dates ON audit_archives(date_range_start, date_range_end);

CREATE TABLE IF NOT EXISTS social_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    provider_key VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    icon_url VARCHAR(500) DEFAULT '',
    button_color VARCHAR(20) DEFAULT '',
    button_text VARCHAR(255) DEFAULT '',
    auto_create_users BOOLEAN DEFAULT true,
    auto_link_by_email BOOLEAN DEFAULT true,
    default_role VARCHAR(255) DEFAULT 'user',
    allowed_domains JSONB DEFAULT '[]',
    attribute_mapping JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_social_providers_key ON social_providers(provider_key);

CREATE TABLE IF NOT EXISTS federation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email_domain VARCHAR(255) NOT NULL UNIQUE,
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    priority INTEGER DEFAULT 0,
    auto_redirect BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_federation_rules_domain ON federation_rules(email_domain);

CREATE TABLE IF NOT EXISTS user_identity_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL,
    external_email VARCHAR(255),
    external_username VARCHAR(255),
    display_name VARCHAR(255),
    profile_data JSONB DEFAULT '{}',
    is_primary BOOLEAN DEFAULT false,
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(provider_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_identity_links_user ON user_identity_links(user_id);

CREATE TABLE IF NOT EXISTS custom_claims_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    claim_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    source_value VARCHAR(500) NOT NULL,
    claim_type VARCHAR(50) DEFAULT 'string',
    include_in_id_token BOOLEAN DEFAULT true,
    include_in_access_token BOOLEAN DEFAULT false,
    include_in_userinfo BOOLEAN DEFAULT true,
    condition JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(application_id, claim_name)
);

CREATE INDEX IF NOT EXISTS idx_custom_claims_app ON custom_claims_mappings(application_id);

CREATE TABLE IF NOT EXISTS notification_routing_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    conditions JSONB DEFAULT '{}',
    channels JSONB NOT NULL DEFAULT '["in_app"]',
    template_overrides JSONB DEFAULT '{}',
    priority INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_routing_rules_event ON notification_routing_rules(event_type, enabled);

CREATE TABLE IF NOT EXISTS broadcast_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    channel VARCHAR(50) NOT NULL DEFAULT 'in_app',
    target_type VARCHAR(50) NOT NULL DEFAULT 'all',
    target_ids JSONB DEFAULT '[]',
    priority VARCHAR(20) DEFAULT 'normal',
    scheduled_at TIMESTAMP WITH TIME ZONE,
    sent_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'draft',
    total_recipients INTEGER DEFAULT 0,
    delivered_count INTEGER DEFAULT 0,
    read_count INTEGER DEFAULT 0,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_broadcasts_status ON broadcast_messages(status);

CREATE INDEX IF NOT EXISTS idx_broadcasts_created ON broadcast_messages(created_at DESC);
`

var reconcileTableGapDown = `-- Migration 054 down: drop the reconciled tables (CASCADE so inter-FKs don't block).
DROP TABLE IF EXISTS admin_audit_log CASCADE;
DROP TABLE IF EXISTS admin_delegations CASCADE;
DROP TABLE IF EXISTS api_usage_metrics CASCADE;
DROP TABLE IF EXISTS attestation_campaigns CASCADE;
DROP TABLE IF EXISTS attestation_items CASCADE;
DROP TABLE IF EXISTS audit_archives CASCADE;
DROP TABLE IF EXISTS audit_retention_policies CASCADE;
DROP TABLE IF EXISTS biometric_policies CASCADE;
DROP TABLE IF EXISTS biometric_preferences CASCADE;
DROP TABLE IF EXISTS broadcast_messages CASCADE;
DROP TABLE IF EXISTS bulk_operation_items CASCADE;
DROP TABLE IF EXISTS bulk_operations CASCADE;
DROP TABLE IF EXISTS campaign_runs CASCADE;
DROP TABLE IF EXISTS connection_tests CASCADE;
DROP TABLE IF EXISTS custom_claims_mappings CASCADE;
DROP TABLE IF EXISTS developer_settings CASCADE;
DROP TABLE IF EXISTS email_branding CASCADE;
DROP TABLE IF EXISTS email_templates CASCADE;
DROP TABLE IF EXISTS entitlement_metadata CASCADE;
DROP TABLE IF EXISTS error_catalog CASCADE;
DROP TABLE IF EXISTS external_audit_sync_state CASCADE;
DROP TABLE IF EXISTS feature_adoption CASCADE;
DROP TABLE IF EXISTS federation_rules CASCADE;
DROP TABLE IF EXISTS guacamole_connection_pool CASCADE;
DROP TABLE IF EXISTS guacamole_connections CASCADE;
DROP TABLE IF EXISTS hardware_token_events CASCADE;
DROP TABLE IF EXISTS hardware_tokens CASCADE;
DROP TABLE IF EXISTS health_check_history CASCADE;
DROP TABLE IF EXISTS ip_geolocation_cache CASCADE;
DROP TABLE IF EXISTS ispm_findings CASCADE;
DROP TABLE IF EXISTS ispm_rules CASCADE;
DROP TABLE IF EXISTS ispm_scores CASCADE;
DROP TABLE IF EXISTS lifecycle_executions CASCADE;
DROP TABLE IF EXISTS lifecycle_policies CASCADE;
DROP TABLE IF EXISTS lifecycle_workflows CASCADE;
DROP TABLE IF EXISTS magic_links CASCADE;
DROP TABLE IF EXISTS mfa_bypass_audit CASCADE;
DROP TABLE IF EXISTS mfa_bypass_codes CASCADE;
DROP TABLE IF EXISTS mfa_email_otp CASCADE;
DROP TABLE IF EXISTS mfa_otp_challenges CASCADE;
DROP TABLE IF EXISTS mfa_phone_call CASCADE;
DROP TABLE IF EXISTS mfa_sms CASCADE;
DROP TABLE IF EXISTS notification_routing_rules CASCADE;
DROP TABLE IF EXISTS oauth_playground_sessions CASCADE;
DROP TABLE IF EXISTS passwordless_preferences CASCADE;
DROP TABLE IF EXISTS phone_call_challenges CASCADE;
DROP TABLE IF EXISTS saml_service_providers CASCADE;
DROP TABLE IF EXISTS social_account_links CASCADE;
DROP TABLE IF EXISTS social_providers CASCADE;
DROP TABLE IF EXISTS temp_access_links CASCADE;
DROP TABLE IF EXISTS temp_access_usage CASCADE;
DROP TABLE IF EXISTS unified_audit_events CASCADE;
DROP TABLE IF EXISTS user_identity_links CASCADE;
DROP TABLE IF EXISTS user_risk_baselines CASCADE;
DROP TABLE IF EXISTS webhook_delivery_stats CASCADE;
DROP TABLE IF EXISTS ziti_edge_routers CASCADE;
DROP TABLE IF EXISTS ziti_metrics CASCADE;
DROP TABLE IF EXISTS ziti_user_sync CASCADE;
`
