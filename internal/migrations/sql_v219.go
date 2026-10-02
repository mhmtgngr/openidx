package migrations

// Migration v219 -- a vendor organization's closed list.
//
// Invariant I11 of the third-party access framework: an organization may put
// a vendor on a closed list, and then the vendor's external users may ask for
// -- and launch -- only what was opened to that vendor. closed_list is the
// switch, off by default so nothing changes for a vendor until an
// administrator turns it on; vendor_org_targets names what is open: a PAM
// entry, an application or a network service, by id. The request path and
// the PAM launch paths read both (internal/externalid.CheckTargetOpen).
//
// A tenant table, belted like vendor_organizations: FORCE RLS on org_id, with
// the bypass the background sweeps use. A target row goes with its vendor.
// Down drops the table and the column; the vendors' external users can then
// ask for anything their grants let them see, as before.

var vendorClosedListUp = `-- Migration 219: a vendor organization's closed list.
ALTER TABLE vendor_organizations ADD COLUMN IF NOT EXISTS closed_list BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS vendor_org_targets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL,
    vendor_org_id UUID NOT NULL REFERENCES vendor_organizations(id) ON DELETE CASCADE,
    target_type   VARCHAR(32) NOT NULL
                  CHECK (target_type IN ('pam_entry','application','network_service')),
    target_id     UUID NOT NULL,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vendor_org_targets_once UNIQUE (vendor_org_id, target_type, target_id)
);
CREATE INDEX IF NOT EXISTS idx_vendor_org_targets_org_id ON vendor_org_targets (org_id);

DROP POLICY IF EXISTS pol_vendor_org_targets_org_scope ON vendor_org_targets;
CREATE POLICY pol_vendor_org_targets_org_scope ON vendor_org_targets
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE vendor_org_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE vendor_org_targets FORCE  ROW LEVEL SECURITY;
`

var vendorClosedListDown = `-- Migration 219 down.
DROP TABLE IF EXISTS vendor_org_targets;
ALTER TABLE vendor_organizations DROP COLUMN IF EXISTS closed_list;
`
