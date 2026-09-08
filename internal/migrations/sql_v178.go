package migrations

// v178 — retire the seeded "Q1 2026 Access Review".
//
// v10 ships starter data, and among the roles, applications and OAuth clients
// it seeds one access review:
//
//	INSERT INTO access_reviews (...) VALUES
//	('70000000-...-000000000001', 'Q1 2026 Access Review',
//	 'Quarterly access review for all users', 'user-access', 'pending',
//	 <the seeded admin>, '2026-01-01', '2026-03-31')
//
// Pending, with an end_date that passed in March. The rest of v10's seed is
// functional starter data an operator builds on; this row is a fixture, and the
// only thing that consults it is the compliance report.
//
// Which did not notice, because the overdue count asked for a column the table
// does not have (access_reviews.due_date; the deadline is end_date), failed to
// plan and read 0. Correcting that query -- in the same commit as this
// migration -- would otherwise hand every install a permanent "1 access review
// overdue" on its SOC 2 report, a finding no operator created and none can
// close by doing their job. A fabricated finding on a compliance report is the
// same defect as a fabricated zero, pointing the other way.
//
// Deleted only if untouched: still pending, still carrying the seeded dates. An
// install where somebody actually ran this campaign keeps it.
const seededAccessReviewUp = `-- Migration 178: retire v10's demo access review.

DELETE FROM access_reviews
WHERE id = '70000000-0000-0000-0000-000000000001'
  AND status = 'pending'
  AND start_date::date = DATE '2026-01-01'
  AND end_date::date   = DATE '2026-03-31';
`

// Down restores it exactly as v10 wrote it, so a rollback lands on the schema
// and data the chain describes. org_id takes the column default (the primary
// organization), which is what v34 gave the row when it scoped the table.
const seededAccessReviewDown = `
INSERT INTO access_reviews (id, name, description, type, status, reviewer_id, start_date, end_date) VALUES
('70000000-0000-0000-0000-000000000001', 'Q1 2026 Access Review', 'Quarterly access review for all users', 'user-access', 'pending', '00000000-0000-0000-0000-000000000001', '2026-01-01', '2026-03-31')
ON CONFLICT (id) DO NOTHING;
`
