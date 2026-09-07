package admin

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// tileQuery runs the one-row aggregates a dashboard card is made of and
// remembers the first that could not be taken.
//
// WHY THIS EXISTS. Every number on these surfaces -- authentication analytics,
// usage analytics, feature adoption, predictive capacity, the AI-agent and
// recommendation tiles, the entitlement counters -- is an aggregate, and an
// aggregate returns exactly one row, always. So a failed Scan here can never
// mean "there is nothing to count". It means the query did not run, and the
// destination keeps its zero, which the handler then serves as a measurement.
//
// A dashboard reading "0 failed logins, 0 high-risk sign-ins, 0 alerts" is
// exactly what a healthy install looks like. That is the whole problem: the
// operator reads it as evidence that nothing is happening, on the surface where
// they decide whether to look further. An error is the only thing that ever
// separated the two, and it was discarded.
//
// The console has an error state for these cards (QueryGate), so a 500 renders
// as "this could not be loaded" -- which is true, and which a zero is not.
type tileQuery struct {
	ctx    context.Context
	s      *Service
	err    error
	metric string
}

func (s *Service) newTileQuery(ctx context.Context) *tileQuery {
	return &tileQuery{ctx: ctx, s: s}
}

// scan reads one aggregate into dest. `name` is what the number is called on
// the card, so the log line names the tile that could not be drawn.
func (q *tileQuery) scan(name string, dest any, sql string, args ...any) {
	if q.err != nil {
		return
	}
	if q.s.db == nil || q.s.db.Pool == nil {
		q.err, q.metric = fmt.Errorf("no database"), name
		return
	}
	if err := q.s.db.Pool.QueryRow(q.ctx, sql, args...).Scan(dest); err != nil {
		q.err, q.metric = err, name
	}
}

// failed answers the request with a 500 when a measurement could not be taken,
// and reports whether it did. The caller returns immediately if it did.
func (q *tileQuery) failed(c *gin.Context) bool {
	if q.err == nil {
		return false
	}
	q.s.logger.Error("a dashboard measurement could not be taken",
		zap.String("metric", q.metric), zap.Error(q.err))
	c.JSON(http.StatusInternalServerError, gin.H{
		"error": "could not measure " + q.metric,
	})
	return true
}

// err reports the failure without answering, for the callers that are not gin
// handlers and return an error of their own.
func (q *tileQuery) failure() error {
	if q.err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", q.metric, q.err)
}
