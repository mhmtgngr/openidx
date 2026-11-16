package migrations

// Migration 260: which model an organization's assistant uses.
//
// org_agentic_settings (v259) gains the provider choice: none (the default:
// the assistant answers from the rule engine's own words, no model is called),
// anthropic (the Claude API) or openai_compat (a model the organization runs,
// behind an OpenAI-compatible endpoint). The API key is stored encrypted.
//
// A model in someone else's cloud is an organization's explicit decision, so
// choosing anthropic needs a recorded consent (who, when) and masking above
// "off"; the CHECK holds both even if a caller forgets.

var agenticProviderUp = `-- Migration 260: assistant provider settings.
ALTER TABLE org_agentic_settings
    ADD COLUMN IF NOT EXISTS provider         VARCHAR(16)  NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS model            VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS base_url         VARCHAR(512) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS redaction        VARCHAR(8)   NOT NULL DEFAULT 'mask',
    ADD COLUMN IF NOT EXISTS api_key_enc      TEXT         NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS tools_enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS cloud_consent_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cloud_consent_by UUID;
ALTER TABLE org_agentic_settings DROP CONSTRAINT IF EXISTS org_agentic_settings_provider_check;
ALTER TABLE org_agentic_settings ADD CONSTRAINT org_agentic_settings_provider_check
    CHECK (provider IN ('none', 'anthropic', 'openai_compat'));
ALTER TABLE org_agentic_settings DROP CONSTRAINT IF EXISTS org_agentic_settings_redaction_check;
ALTER TABLE org_agentic_settings ADD CONSTRAINT org_agentic_settings_redaction_check
    CHECK (redaction IN ('off', 'mask', 'strict'));
ALTER TABLE org_agentic_settings DROP CONSTRAINT IF EXISTS org_agentic_settings_cloud_consent_check;
ALTER TABLE org_agentic_settings ADD CONSTRAINT org_agentic_settings_cloud_consent_check
    CHECK (provider <> 'anthropic' OR (cloud_consent_at IS NOT NULL AND redaction <> 'off'));
`

var agenticProviderDown = `-- Rollback migration 260.
ALTER TABLE org_agentic_settings DROP CONSTRAINT IF EXISTS org_agentic_settings_cloud_consent_check;
ALTER TABLE org_agentic_settings DROP CONSTRAINT IF EXISTS org_agentic_settings_redaction_check;
ALTER TABLE org_agentic_settings DROP CONSTRAINT IF EXISTS org_agentic_settings_provider_check;
ALTER TABLE org_agentic_settings
    DROP COLUMN IF EXISTS cloud_consent_by,
    DROP COLUMN IF EXISTS cloud_consent_at,
    DROP COLUMN IF EXISTS tools_enabled,
    DROP COLUMN IF EXISTS api_key_enc,
    DROP COLUMN IF EXISTS redaction,
    DROP COLUMN IF EXISTS base_url,
    DROP COLUMN IF EXISTS model,
    DROP COLUMN IF EXISTS provider;
`
