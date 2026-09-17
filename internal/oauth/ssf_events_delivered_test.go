package oauth

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// A STREAM CONFIGURATION THAT SAYS WHAT THE STREAM WILL GET.
//
// The discovery document was made honest earlier: events_supported names what
// this transmitter emits and nothing else. This is the same honesty one step
// later. A receiver posts events_requested; SSF answers with events_delivered,
// the intersection with what is supported, and OpenIDX answered with the
// request echoed back and an enabled stream. A receiver that asked for
// credential-change -- which this transmitter has never sent -- was told
// nothing, and waited.
//
// So: events_delivered is computed from the SAME list the discovery document
// advertises, an empty request means everything (the reading the emit side
// already gives it), and a request that intersects to nothing is refused with
// the offered list in the error, where the receiver's operator is looking.

func TestEventsDeliveredIsTheRequestReducedToWhatIsEmitted(t *testing.T) {
	cases := []struct {
		name      string
		requested []string
		want      []string
	}{
		{"nothing requested means everything supported", nil, ssfEventsSupported},
		{"an empty list is the same as nothing", []string{}, ssfEventsSupported},
		{"a supported event is delivered", []string{EventSessionRevoked}, []string{EventSessionRevoked}},
		{"an unsupported event is dropped, the supported one kept",
			[]string{EventCredentialChange, EventAccountDisabled}, []string{EventAccountDisabled}},
		{"only unsupported events deliver nothing", []string{EventCredentialChange, EventTokenClaimsChange}, []string{}},
		{"an unknown URI is not a supported event", []string{"https://example.test/not-an-event"}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ssfEventsDelivered(tc.requested)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("ssfEventsDelivered(%v) = %v, want %v", tc.requested, got, tc.want)
			}
		})
	}
}

// The emit side and the configuration side must read an empty request the
// same way, or the configuration would promise one set and the fan-out
// deliver another. Both say "everything".
func TestAnEmptyRequestMeansEverythingOnBothSides(t *testing.T) {
	for _, ev := range ssfEventsSupported {
		if !streamWantsEvent([]byte(`[]`), ev) {
			t.Errorf("the emit side does not deliver %s to a stream with no events_requested", ev)
		}
	}
	if len(ssfEventsDelivered(nil)) != len(ssfEventsSupported) {
		t.Errorf("the configuration side promises %v for an empty request; the emit side delivers everything", ssfEventsDelivered(nil))
	}
}

// The refusal happens before anything is written, so it needs no database:
// a Service with no pool proves the check sits in front of the INSERT.
func TestAStreamThatCouldNeverDeliverIsRefusedWithTheOfferedList(t *testing.T) {
	svc := &Service{logger: zap.NewNop()}
	_, err := svc.CreateSSFStream(context.Background(), "00000000-0000-0000-0000-0000000000aa", &SSFStreamInput{
		Audience: "https://rp.example.test", DeliveryEndpoint: "https://rp.example.test/ssf",
		EventsRequested: []string{EventCredentialChange},
	})
	if err == nil {
		t.Fatal("a stream requesting only events this transmitter never emits was created; it would stay silent forever")
	}
	for _, ev := range ssfEventsSupported {
		if !strings.Contains(err.Error(), ev) {
			t.Errorf("the refusal does not name %s, so the operator cannot see what to ask for instead: %v", ev, err)
		}
	}
}

// The variable the discovery document advertises is the one events_delivered
// is computed from. Pinned here as a value check beside the census's source
// check: an emitted event is both advertised and deliverable, in one list.
func TestWhatIsAdvertisedIsWhatCanBeDelivered(t *testing.T) {
	if len(ssfEventsSupported) == 0 {
		t.Fatal("ssfEventsSupported is empty; the transmitter offers nothing")
	}
	got := ssfEventsDelivered(ssfEventsSupported)
	if strings.Join(got, ",") != strings.Join(ssfEventsSupported, ",") {
		t.Errorf("requesting exactly the advertised list delivers %v", got)
	}
}
