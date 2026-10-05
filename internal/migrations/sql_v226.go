package migrations

// Migration v226 -- an approval row records why its approver is on it, so the
// approver is held to that at the decision.
//
// An approval step names approvers when the request is filed: a role or a
// group step expands to the holders of the role or the members of the group
// that day, a manager step to the requester's manager, and an external user's
// request starts with their sponsor. Each becomes a row naming one user, and
// nothing on the row said which of those it was. So a holder whose role or
// membership ended, a manager the requester no longer reports to, or a sponsor
// who handed the account over, could still decide the request: the row was
// the whole authority, and the reason for it was gone.
//
// approver_basis is that reason ('user', 'role', 'group', 'manager',
// 'sponsor', 'default'), and approver_basis_id the role or group a 'role' or
// 'group' row came from. governance-service writes both when it builds the
// chain, and re-reads the basis when the approver decides. A row written
// before this migration has none, and is decided as before.
//
// Down drops the constraint and the columns.

var approvalRowBasisUp = `-- Migration 226: an approval row records why its approver is on it.
ALTER TABLE access_request_approvals ADD COLUMN IF NOT EXISTS approver_basis VARCHAR(16);
ALTER TABLE access_request_approvals ADD COLUMN IF NOT EXISTS approver_basis_id UUID;
ALTER TABLE access_request_approvals DROP CONSTRAINT IF EXISTS access_request_approvals_basis_check;
ALTER TABLE access_request_approvals ADD CONSTRAINT access_request_approvals_basis_check
    CHECK (approver_basis IS NULL OR approver_basis IN ('user', 'role', 'group', 'manager', 'sponsor', 'default'));
`

var approvalRowBasisDown = `-- Migration 226 down: approval rows no longer record their basis.
ALTER TABLE access_request_approvals DROP CONSTRAINT IF EXISTS access_request_approvals_basis_check;
ALTER TABLE access_request_approvals DROP COLUMN IF EXISTS approver_basis_id;
ALTER TABLE access_request_approvals DROP COLUMN IF EXISTS approver_basis;
`
