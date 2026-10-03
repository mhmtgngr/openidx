package oauth

import (
	"testing"

	"github.com/openidx/openidx/internal/common/ssfsignal"
)

// ssfsignal spells the event URI itself so producers never import this
// package. Two spellings of one URI is how a receiver subscribed to the
// advertised event silently receives nothing.
func TestTheProducerAndTheTransmitterAgreeOnTheEventURI(t *testing.T) {
	for _, c := range []struct{ name, producer, transmitter string }{
		{"AccountDisabled", ssfsignal.AccountDisabled, EventAccountDisabled},
		{"SessionRevoked", ssfsignal.SessionRevoked, EventSessionRevoked},
		{"TokenClaimsChange", ssfsignal.TokenClaimsChange, EventTokenClaimsChange},
	} {
		if c.producer != c.transmitter {
			t.Errorf("ssfsignal.%s=%q, oauth.Event%s=%q", c.name, c.producer, c.name, c.transmitter)
		}
	}
}
