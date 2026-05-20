-- 202605150003: Kiosk policy storage for Phase 3 of the Android client.
--
-- A kiosk_policies row is a self-contained description of what the device
-- should look like in kiosk mode (which apps are allowed, which lock-task
-- features the user can access, optional branding). kiosk_policy_assignments
-- maps a policy to a target — either a specific agent or a tag / group that
-- the agent belongs to — with a precedence order: direct agent assignment
-- beats group assignment beats tag assignment.
--
-- /agent/config resolves the effective policy at request time so admins can
-- re-target policies without re-publishing them to every device.

CREATE TABLE IF NOT EXISTS kiosk_policies (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 VARCHAR(128) NOT NULL,
    description          TEXT,
    -- Mode controls the kiosk's overall shape:
    --   "single_app"   — pin one app, hide the home / recents / status bar
    --   "multi_app"    — allow a curated set of apps, custom launcher inside
    --                    the agent. The user can switch between them.
    --   "off"          — explicit "not in kiosk"; lets admins disable on a
    --                    group without deleting the policy.
    mode                 VARCHAR(16) NOT NULL DEFAULT 'multi_app',
    -- JSONB array of Android package names allowed in kiosk mode.
    allowed_packages     JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- The activity component to pin when mode='single_app'. Empty otherwise.
    primary_activity     VARCHAR(255),
    -- DevicePolicyManager.setLockTaskFeatures flags packed as a JSON array
    -- of feature names: ["home","notifications","global_actions","system_info",
    --                    "keyguard","overview","blocked_activity"]. The agent
    -- translates these to LOCK_TASK_FEATURE_* int constants.
    lock_task_features   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Branding payload (logo url, wallpaper url, name). Optional; agent
    -- ignores unknown keys.
    branding             JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- SHA-256 of the exit PIN that lets an on-site admin temporarily leave
    -- kiosk mode. NULL means "no exit PIN; kiosk can only be left by
    -- revoking the agent or pushing a new policy with mode='off'".
    exit_pin_hash        VARCHAR(128),
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_kiosk_policies_enabled
    ON kiosk_policies(enabled) WHERE enabled = TRUE;

CREATE TABLE IF NOT EXISTS kiosk_policy_assignments (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id    UUID NOT NULL REFERENCES kiosk_policies(id) ON DELETE CASCADE,
    -- target_kind: 'agent' | 'group' | 'tag'.
    --   agent → target_id is enrolled_agents.agent_id (VARCHAR)
    --   group → target_id is a group identifier from identity service
    --   tag   → target_id is a free-form string matched against
    --           enrolled_agents.metadata->>'tags' (JSONB array, future)
    target_kind  VARCHAR(16) NOT NULL,
    target_id    VARCHAR(128) NOT NULL,
    -- priority lets admins force a higher-precedence assignment without
    -- changing target_kind. Bigger wins. Defaults follow the natural
    -- agent > group > tag ordering (300/200/100).
    priority     INT NOT NULL DEFAULT 100,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (policy_id, target_kind, target_id)
);

CREATE INDEX IF NOT EXISTS idx_kiosk_assignments_target
    ON kiosk_policy_assignments(target_kind, target_id);
