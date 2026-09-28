package migrations

// Migration v206 -- the two columns that let an approval policy's step order,
// min_approvals and max_wait_hours decide anything.
//
// approval_policies has stored max_wait_hours since v1, and each step in its
// approval_steps JSON has carried order and min_approvals, and the console has
// shown all three. None of them decided anything: every approver row had to
// approve whatever a step said, the rows of every step were live at once, and
// a request nobody answered stayed pending forever. The workflow now enforces
// them, and it needs two facts recorded at the moment a request is created,
// because a policy may be edited while a request is open and the request must
// keep the terms it was filed under:
//
//   - access_request_approvals.step_min_approvals: how many approvals the
//     row's step needs, copied from the policy step onto every row of that
//     step. DEFAULT 1 fills every row that exists: the old behaviour required
//     every row, and the documented step semantics ("any user with the role")
//     are one, so an open request keeps advancing under the reading its
//     approvers were shown.
//   - access_requests.answer_by: when an unanswered request expires, set from
//     the policy's max_wait_hours at creation. NULL for requests filed before
//     this and for requests no policy governs, which keep waiting as they
//     always have.
//
// Down drops both columns; an install rolling back to v205 runs code that
// reads neither.

var approvalPolicyFieldsUp = `-- Migration 206: record the approval terms a request was filed under.
ALTER TABLE access_request_approvals ADD COLUMN IF NOT EXISTS step_min_approvals INTEGER NOT NULL DEFAULT 1;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS answer_by TIMESTAMP WITH TIME ZONE;
CREATE INDEX IF NOT EXISTS idx_access_requests_answer_by ON access_requests(answer_by) WHERE status = 'pending' AND answer_by IS NOT NULL;
`

var approvalPolicyFieldsDown = `-- Migration 206 down: drop the recorded approval terms.
DROP INDEX IF EXISTS idx_access_requests_answer_by;
ALTER TABLE access_requests DROP COLUMN IF EXISTS answer_by;
ALTER TABLE access_request_approvals DROP COLUMN IF EXISTS step_min_approvals;
`
