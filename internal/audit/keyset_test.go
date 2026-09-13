package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventCursorRoundTrips(t *testing.T) {
	want := EventCursor{
		// Nanosecond precision on purpose: the tie-break only works if the
		// cursor carries the timestamp the row actually has.
		Timestamp: time.Date(2026, 9, 13, 14, 5, 6, 123456789, time.UTC),
		ID:        "0f8fad5b-d9cb-469f-a165-70867728950e",
	}
	got, err := DecodeEventCursor(want.Encode())
	require.NoError(t, err)
	assert.True(t, want.Timestamp.Equal(got.Timestamp),
		"timestamp did not survive the round trip: %s vs %s", want.Timestamp, got.Timestamp)
	assert.Equal(t, want.ID, got.ID)
}

// A cursor is a position, not a promise. It is encoded so a client cannot
// build one by hand out of an ordering that may change.
func TestEventCursorIsOpaque(t *testing.T) {
	enc := EventCursor{Timestamp: time.Now(), ID: "abc"}.Encode()
	assert.NotContains(t, enc, "abc")
	assert.NotContains(t, enc, "|")
}

// Every malformed cursor is an error, never a silent fall back to the first
// page: that would hand the caller a page they have already read and call it
// the next one.
func TestDecodeEventCursorRejectsGarbage(t *testing.T) {
	valid := EventCursor{Timestamp: time.Now().UTC(), ID: "0f8fad5b-d9cb-469f-a165-70867728950e"}.Encode()

	cases := map[string]string{
		"empty":           "",
		"not base64":      "!!!not base64!!!",
		"too few fields":  b64("v1|2026-09-13T00:00:00Z"),
		"wrong version":   b64("v2|2026-09-13T00:00:00Z|abc"),
		"bad timestamp":   b64("v1|not-a-time|abc"),
		"no id":           b64("v1|2026-09-13T00:00:00Z|"),
		"truncated valid": valid[:len(valid)-4],
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeEventCursor(raw)
			assert.Error(t, err, "a %s cursor was accepted", name)
		})
	}
}

func b64(s string) string {
	return EventCursor{}.encodeRawForTest(s)
}

// The ordering is a decision, so it is pinned as one.
//
// A behavioural test cannot be relied on here: removing the tie-break leaves
// the paging tests green, because Postgres returns tied rows in the order of
// the index it chose and v190's index carries id. The guarantee has to come
// from the ORDER BY -- the planner is free to pick a sort instead, and then
// tied rows arrive in heap order and a row lands on two pages or on neither.
// On an audit log that is the worst available wrong answer.
func TestEventOrderingIsTotal(t *testing.T) {
	assert.Equal(t, "ORDER BY timestamp DESC, id DESC", eventOrdering,
		"timestamp alone is not a total order: the column defaults to NOW() and a burst writes several rows in the same microsecond")
}
