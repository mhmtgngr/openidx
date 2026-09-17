package oauth

import (
	"testing"

	"github.com/openidx/openidx/internal/common/ssfsignal"
)

// ssfsignal spells the event URI itself so producers never import this
// package. Two spellings of one URI is how a receiver subscribed to the
// advertised event silently receives nothing.
func TestTheProducerAndTheTransmitterAgreeOnTheEventURI(t *testing.T) {
	if ssfsignal.AccountDisabled != EventAccountDisabled {
		t.Fatalf("ssfsignal.AccountDisabled=%q, oauth.EventAccountDisabled=%q", ssfsignal.AccountDisabled, EventAccountDisabled)
	}
}
