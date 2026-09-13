package audit

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Keyset pagination for the audit event list (global-scale plan task 2.5).
//
// WHAT OFFSET COSTS. `ORDER BY timestamp DESC OFFSET 50000 LIMIT 50` asks
// Postgres to produce fifty thousand rows and throw them away before returning
// the fifty the caller wanted. The work grows with the page NUMBER, so the
// deepest pages -- an auditor walking a year of events, or an export that
// pages to the end -- are the slowest, and on a 50M-row table they are slow
// enough to hold a backend for seconds. Under the plane's statement_timeout
// (task 2.4) they now get cancelled instead, which is better than a stall and
// still not an answer.
//
// A cursor costs the same at page 1 and page 100,000: the WHERE clause names
// where to resume, the index seeks straight there, and LIMIT stops.
//
// THE TIE-BREAK IS NOT DECORATION. `ORDER BY timestamp DESC` alone is not a
// total order: audit_events.timestamp defaults to NOW(), and a burst writes
// several rows in the same microsecond. Postgres may return tied rows in any
// order, and it need not be the same order twice -- so with OFFSET paging, a
// row can appear on two consecutive pages or on neither, which on an audit log
// is the one thing that must not happen. Ordering by (timestamp, id) makes it
// total, and the cursor carries both.
//
// WHAT THIS DOES NOT FIX BY ITSELF: the COUNT. See QueryEvents.

// eventOrdering is the total order the event list is paged in, and the only
// place it is written down. Both the cursor path and the offset path use it,
// because a cursor that resumes in one order while the page is produced in
// another is not a cursor at all.
//
// WHY IT IS PINNED BY A TEST RATHER THAN BY BEHAVIOUR. Removing `, id DESC`
// leaves the paging tests green: Postgres happens to return tied rows in the
// index's own order, and v190's index carries id, so the hazard stays latent.
// It is still real -- the guarantee comes from the ORDER BY, not from a plan
// the planner is free to change, and the day it picks a sort over a seq scan
// the ties come back in heap order and a row appears on two pages or on
// neither. So the ordering is a decision, pinned as one.
const eventOrdering = "ORDER BY timestamp DESC, id DESC"

// cursorVersion prefixes the encoded value so a future change of shape is a
// clean rejection rather than a mis-parse that silently pages from the wrong
// place.
const cursorVersion = "v1"

// EventCursor is a position in the (timestamp DESC, id DESC) ordering: the last
// row the caller was given. The next page is everything strictly after it.
type EventCursor struct {
	Timestamp time.Time
	ID        string
}

// Encode renders the cursor as the opaque string the API hands back. Opaque
// because it is a position, not a promise: a client that takes it apart and
// builds its own would be depending on the ordering never changing.
func (c EventCursor) Encode() string {
	raw := fmt.Sprintf("%s|%s|%s", cursorVersion, c.Timestamp.UTC().Format(time.RFC3339Nano), c.ID)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeEventCursor parses a cursor produced by Encode.
//
// Every failure is the same failure to the caller -- a bad cursor -- because
// the alternatives are worse: silently starting from the beginning would hand
// an auditor a page they have already seen and call it the next one, and
// silently returning nothing would look like the end of the log.
func DecodeEventCursor(s string) (EventCursor, error) {
	if s == "" {
		return EventCursor{}, fmt.Errorf("empty cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return EventCursor{}, fmt.Errorf("cursor is not valid base64url: %w", err)
	}
	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 {
		return EventCursor{}, fmt.Errorf("cursor has %d fields, want 3", len(parts))
	}
	if parts[0] != cursorVersion {
		return EventCursor{}, fmt.Errorf("cursor version %q is not %q", parts[0], cursorVersion)
	}
	ts, err := time.Parse(time.RFC3339Nano, parts[1])
	if err != nil {
		return EventCursor{}, fmt.Errorf("cursor timestamp: %w", err)
	}
	if parts[2] == "" {
		return EventCursor{}, fmt.Errorf("cursor carries no id; the ordering would not be total")
	}
	// audit_events.id is a UUID and the query casts the cursor's id to one, so
	// a malformed id that got this far would come back as a 500 from the
	// database rather than a 400 from here. It is also the case a truncated
	// cursor lands in: lopping characters off a valid one leaves something
	// that still splits into three fields, and only the UUID shape catches it.
	if _, err := uuid.Parse(parts[2]); err != nil {
		return EventCursor{}, fmt.Errorf("cursor id is not a uuid: %w", err)
	}
	return EventCursor{Timestamp: ts, ID: parts[2]}, nil
}

// encodeRawForTest base64-encodes an already-assembled cursor body. It exists
// so the decoder's tests can hand it malformed bodies without reimplementing
// the transport and drifting from it.
func (c EventCursor) encodeRawForTest(raw string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}
