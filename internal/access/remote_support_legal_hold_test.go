package access

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestIsUniqueViolation_RecognizesPgError23505 confirms the helper
// catches the SQLSTATE that the recording_legal_holds partial unique
// index throws when a second active hold is attempted. If this test
// fails the place-hold handler will return 500 instead of 409 for the
// "already held" case, which is poor UX but not a security issue.
func TestIsUniqueViolation_RecognizesPgError23505(t *testing.T) {
	err := &pgconn.PgError{Code: "23505"}
	assert.True(t, isUniqueViolation(err), "23505 must be recognized as unique violation")
}

func TestIsUniqueViolation_RejectsOtherCodes(t *testing.T) {
	err := &pgconn.PgError{Code: "23503"} // foreign-key violation
	assert.False(t, isUniqueViolation(err))

	wrapped := errors.New("plain string")
	assert.False(t, isUniqueViolation(wrapped))
}

// TestHasActiveLegalHold_NilDBReturnsFalse covers the dev-mode path
// where the handler is constructed without a database. The sweeper
// should still execute (other code paths) but treat every session as
// "not held".
func TestHasActiveLegalHold_NilDBReturnsFalse(t *testing.T) {
	h := &RemoteSupportHandler{logger: zap.NewNop()}
	held, err := h.hasActiveLegalHold(nil, "any-session")
	assert.NoError(t, err)
	assert.False(t, held)
}
