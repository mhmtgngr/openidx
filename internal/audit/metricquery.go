package audit

import (
	"context"
	"errors"
	"fmt"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// errNoComplianceDatabase is what a report generator gets when there is no
// database to measure. It is an error and not an empty report on purpose: see
// metricQuery.
var errNoComplianceDatabase = errors.New("compliance metrics require a database")

// metricQuery runs the one-row aggregates a compliance section is made of and
// remembers the first that failed.
//
// WHY THIS TYPE EXISTS. Every measurement in a compliance report is an
// aggregate -- COUNT, SUM, AVG, MAX -- and an aggregate returns exactly one
// row, always. So Scan on one of these can never mean "there is no data". It
// means the query did not run: a column that is not there, a policy that
// refused, a connection that died, an organization context that never arrived.
//
// Every one of those left the destination at its zero value, and the report
// published that zero as a measurement. Not as "unknown", not as an error --
// as a number, in a document an auditor reads as evidence. "0 overdue access
// reviews." "0 data-subject requests outstanding." "Average session length: 0
// hours." This file has already been caught doing exactly that twice: the
// overdue-review count queried a due_date column access_reviews does not have,
// and the average-session query named created_at on a table whose column is
// started_at. Both were found by a tool that plans the SQL, not by anything in
// this package -- because nothing in this package was looking at the error.
//
// So: an aggregate that fails is a failed report. The generator returns the
// error and the endpoint answers 500. A compliance report is the one document
// where "I could not measure this" must never be rendered as a measurement.
//
// Absent data is still zero, which is the point of the distinction: COUNT over
// no rows returns 0 and that is a fact, indistinguishable in the destination
// from the false zero, and only the error told them apart.
type metricQuery struct {
	ctx   context.Context
	pool  scalarQuerier
	orgID string
	err   error
}

// scalarQuerier is the slice of pgxpool this type uses, named so the self-test
// can substitute a failing one without a database.
type scalarQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) rowScanner
}

type rowScanner interface {
	Scan(dest ...any) error
}

// newMetricQuery binds a report section to the tenant it is being written for.
//
// The organization is required. Every query below filters on org_id, and the
// old code read it with `org, _ := orgctx.From(ctx)`: with no organization in
// context that yields the empty string, an org_id predicate against it fails
// to parse as a UUID, and EVERY metric in the section comes back zero. A
// report that is all zeros
// because nobody said which tenant it was for is the worst version of this
// defect, and it was one discarded error away at all times.
func (s *Service) newMetricQuery(ctx context.Context) *metricQuery {
	q := &metricQuery{ctx: ctx}
	org, err := orgctx.From(ctx)
	if err != nil {
		q.err = fmt.Errorf("compliance report needs an organization context: %w", err)
		return q
	}
	q.orgID = org.ID
	if s.db == nil || s.db.Pool == nil {
		q.err = errNoComplianceDatabase
		return q
	}
	q.pool = poolScalarQuerier{s}
	return q
}

type poolScalarQuerier struct{ s *Service }

func (p poolScalarQuerier) QueryRow(ctx context.Context, sql string, args ...any) rowScanner {
	return p.s.db.Pool.QueryRow(ctx, sql, args...)
}

// org is the tenant this section is being measured for.
func (q *metricQuery) org() string { return q.orgID }

// scan runs one aggregate into dest. `name` is what the metric is called in
// the report, so an operator reading the 500 knows which measurement could not
// be taken rather than only that something failed.
//
// After the first failure the rest are skipped: the report is already not going
// to be published, and running twenty more queries against a database that just
// refused one buys nothing.
func (q *metricQuery) scan(name string, dest any, sql string, args ...any) {
	if q.err != nil {
		return
	}
	if q.pool == nil {
		q.err = errNoComplianceDatabase
		return
	}
	if err := q.pool.QueryRow(q.ctx, sql, args...).Scan(dest); err != nil {
		q.err = fmt.Errorf("%s: %w", name, err)
	}
}

// failed reports whether any measurement in this section could not be taken.
func (q *metricQuery) failed() error { return q.err }
