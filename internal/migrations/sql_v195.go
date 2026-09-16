package migrations

// Migration v195 -- the tenant directory: which cell serves which org.
//
// WHAT THIS IS FOR, AND WHY IT IS NOT THE 421. v194's neighbour in the plan
// (task 4.1) has two halves that are easy to conflate. cell.Guard answers 421
// Misdirected Request to a token stamped with another cell: that is the
// BACKSTOP, behind a routing decision that was already made and was wrong.
// This table is the routing decision itself -- the record of where a tenant
// lives, which the edge reads to send the request to the right cell in the
// first place. The directory makes the common case right; the 421 makes the
// uncommon case legible. Neither substitutes for the other.
//
// THE GAP THIS CLOSES IN THE BACKSTOP, which is the reason it is not merely the
// nicer half. The issuer stamps the cell it MINTED a token in. That catches a
// token carried from one cell to another, and it does not catch a LOGIN that
// reached the wrong cell: an eu-1 issuer serving a us-1 tenant mints cell=eu-1,
// every eu-1 guard compares eu-1 against eu-1, and the request is served by a
// database that does not hold that tenant -- the confident 404 the 421 exists
// to replace, arriving through the one door the guard cannot watch. With this
// table the issuer can stamp the tenant's HOME cell instead, and the guard in
// the wrong cell refuses on the first request rather than the hundredth.
//
// NO FOREIGN KEY TO organizations, and this is the whole point rather than an
// omission. Every other tenant table in this schema references organizations(id)
// -- outbox does, and v192's comment argues for it. This one must not. In a
// celled deployment the directory is GLOBAL and the organizations table is
// PER-CELL: eu-1's database holds eu-1's tenants, and the row that says
// "org X lives in us-1" is precisely a row about an org eu-1's organizations
// table does not have. A foreign key would make the directory unable to record
// the only fact it exists to record. The cost is real and is stated rather than
// discovered: nothing deletes a placement when an org is deleted, so the
// control plane owns that, and an orphaned placement names a tenant that is
// gone rather than corrupting one that is not.
//
// cell_id IS CHECKED NON-EMPTY because of how the reader downstream behaves.
// cell.Misdirected treats an empty cell as "this token predates the claim" and
// SERVES the request; a placement row with an empty cell_id would therefore
// read, everywhere downstream, as a tenant that is not placed at all -- placed
// nowhere and refused by nobody. That is a row that reports success while the
// thing it was meant to make true is not true, so the column refuses to hold
// it.
//
// THE BELT. org_id-scoped RLS, forced, applied at creation for v192's reason:
// a table that gets its policy in a later migration spends the interval
// unbelted. A tenant has no business reading where another tenant lives.
// The readers that legitimately cross tenants -- the edge resolver and any
// control-plane placement tool -- do it under orgctx.WithBypassRLS, the same
// way the outbox relay, the SCIM outbound worker and the SSF transmitter
// already do.
var orgCellsUp = `-- Migration 195: the tenant directory.
CREATE TABLE IF NOT EXISTS org_cells (
    org_id     UUID PRIMARY KEY,
    cell_id    TEXT NOT NULL CHECK (cell_id <> ''),
    region     TEXT NOT NULL DEFAULT '',
    residency  TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- "Which tenants does this cell serve" is the question a cell drain, a
-- migration wave and a capacity report all ask. The lookup by org_id is the
-- primary key; this is the other direction.
CREATE INDEX IF NOT EXISTS idx_org_cells_cell ON org_cells (cell_id);

-- Residency is a filter on where a tenant may be placed AT ALL, so the
-- question "is anything in this residency class outside its permitted cells"
-- has to be answerable without scanning. Partial: an unset residency is the
-- default and carries no constraint to audit.
CREATE INDEX IF NOT EXISTS idx_org_cells_residency
    ON org_cells (residency)
    WHERE residency <> '';

DROP POLICY IF EXISTS pol_org_cells_org_scope ON org_cells;
CREATE POLICY pol_org_cells_org_scope ON org_cells
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE org_cells ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_cells FORCE  ROW LEVEL SECURITY;
`

// Down drops the table. A placement is a control-plane record rather than
// tenant data, and an install rolling this back is an install that is not
// celled -- where an empty directory and no directory are the same thing.
var orgCellsDown = `-- Migration 195 down: drop the tenant directory.
DROP TABLE IF EXISTS org_cells;
`
