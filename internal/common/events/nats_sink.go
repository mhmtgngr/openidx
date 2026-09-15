package events

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// THE SINK, AND THE ONE PUBLISH CALL THAT SATISFIES ITS CONTRACT.
//
// Sink.Publish says: returning nil means the broker has ACCEPTED the event. The
// relay deletes the outbox row on that nil, so a sink that returns sooner turns
// at-least-once into at-most-once with nothing visible anywhere. The NATS client
// offers three ways to publish and two of them do exactly that. Measured against
// a real server by publishing 200 messages and counting what the stream held at
// the instant the call returned:
//
//	nc.Publish       (core, fire-and-forget)  33 of 200   0.1 ms total
//	js.PublishAsync  (ack arrives later)      60 of 200   0.6 ms total
//	js.Publish       (waits for PubAck)      200 of 200  32.5 ms total
//
// So js.Publish, and the cost is stated rather than discovered: 163 microseconds
// per event against 0.5. That is the price of the guarantee, and
// no_async_publish_test.go is what stops someone buying the 0.5 back without
// knowing what they sold.
//
// DEDUPLICATION IS WHY THE MESSAGE ID IS SET. The relay is at-least-once BY
// DESIGN -- it publishes, then commits the mark, and a crash between the two
// redelivers. That is the correct trade (a duplicate is recognisable, a lost
// event is not), and it means duplicates are normal traffic rather than an
// incident. JetStream suppresses a repeat of the same Nats-Msg-Id inside the
// stream's duplicate window, so stamping the event id there means the ordinary
// crash-redelivery never reaches a consumer at all. The window has to outlast a
// relay restart to be worth anything, hence two minutes rather than the default.
//
// THE SUBJECT IS BUILT, NOT INTERPOLATED, AND THE TWO HALVES ARE CHECKED
// DIFFERENTLY -- which is the correction an end-to-end test forced.
//
// The first version refused a dot anywhere, on the reasoning that a dot starts
// a new subject token. True, and wrong as a rule: this platform's event types
// ARE dotted (event.go ships user.created and session.revoked), and a hierarchy
// is what a subject is for. A consumer wanting every user event subscribes to
// <prefix>.<org>.user.> precisely because the type has structure. Refusing that
// rejected the vocabulary the rest of the package publishes.
//
// So the tenant token and the type suffix have different rules, because they
// are doing different jobs:
//
//   - The ORG ID occupies one token, and that position is what a per-tenant
//     subscription matches on. A dot there moves the event into another
//     tenant's position, so it stays a single token -- which a UUID already is.
//   - The EVENT TYPE is a hierarchy and may carry dots between non-empty
//     tokens. What it must not carry is `*` or `>`: those are wildcards, and a
//     type of "user.>" publishes across a subtree a narrowly permitted
//     subscriber was never meant to receive. Nor an empty token, which shifts
//     every token after it one position left.
//
// Both refuse whitespace and control characters: a subject is a wire token, and
// the server is not the only thing that reads it.

const (
	// natsDuplicateWindow bounds how far back the broker looks for a repeated
	// message id. Long enough to cover a relay crash and restart, short enough
	// that the broker is not indexing a day of ids.
	natsDuplicateWindow = 2 * time.Minute

	// natsStreamMaxAge is the plan's seven days (task 3.2). Retention is a
	// property of the STREAM, not of the server's config, which is why it lives
	// here and not in the Helm chart.
	natsStreamMaxAge = 7 * 24 * time.Hour

	// natsPublishTimeout bounds one publish. The relay holds a database
	// transaction open across this call, so a sink that hangs is holding a row
	// lock and an idle transaction; the EVENT plane's own budget is 300s, and
	// this is deliberately far inside it.
	natsPublishTimeout = 10 * time.Second
)

// NATSSink publishes outbox deliveries to a JetStream stream.
type NATSSink struct {
	js     jetstream.JetStream
	stream string
	prefix string
}

// NATSSinkConfig configures the sink. Stream and Prefix default to the values
// the Helm chart's subject permissions are written from, so a deployment that
// changes one has to change both and will find out at connect time rather than
// at publish time.
type NATSSinkConfig struct {
	Stream string
	Prefix string
}

const (
	defaultNATSStream = "OPENIDX_EVENTS"
	defaultNATSPrefix = "openidx"
)

// NewNATSSink returns a sink that publishes to stream, creating it if it does
// not exist. Creating it here rather than in a migration or an init container is
// deliberate: the stream's retention and duplicate window are properties this
// code depends on, and a stream somebody else created with different ones would
// change what the relay guarantees without changing the relay.
func NewNATSSink(ctx context.Context, nc *nats.Conn, cfg NATSSinkConfig) (*NATSSink, error) {
	if cfg.Stream == "" {
		cfg.Stream = defaultNATSStream
	}
	if cfg.Prefix == "" {
		cfg.Prefix = defaultNATSPrefix
	}
	if err := validSubjectToken(cfg.Prefix); err != nil {
		return nil, fmt.Errorf("nats sink prefix: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("open jetstream: %w", err)
	}
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       cfg.Stream,
		Subjects:   []string{cfg.Prefix + ".>"},
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
		MaxAge:     natsStreamMaxAge,
		Duplicates: natsDuplicateWindow,
	}); err != nil {
		return nil, fmt.Errorf("ensure stream %s: %w", cfg.Stream, err)
	}
	return &NATSSink{js: js, stream: cfg.Stream, prefix: cfg.Prefix}, nil
}

// Publish implements Sink. It returns only once the broker has acknowledged the
// event -- see the header for what the alternatives cost.
func (s *NATSSink) Publish(ctx context.Context, d Delivery) error {
	subject, err := s.subject(d)
	if err != nil {
		return err
	}
	body, err := json.Marshal(natsEnvelope{
		EventID:   d.EventID,
		EventType: d.EventType,
		OrgID:     d.OrgID,
		Source:    d.Source,
		Payload:   d.Payload,
		Metadata:  d.Metadata,
		CreatedAt: d.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("marshal event %s: %w", d.EventID, err)
	}

	ctx, cancel := context.WithTimeout(ctx, natsPublishTimeout)
	defer cancel()

	// jetstream.WithMsgID is the deduplication key, not a trace field: the
	// broker drops a repeat of it inside the duplicate window, which is what
	// turns the relay's designed redelivery into something a consumer never
	// sees.
	if _, err := s.js.Publish(ctx, subject, body, jetstream.WithMsgID(d.EventID)); err != nil {
		return fmt.Errorf("publish %s to %s: %w", d.EventID, subject, err)
	}
	return nil
}

// natsEnvelope is what a consumer reads. It carries the org id in the BODY as
// well as in the subject, because a consumer that trusts the subject alone is
// trusting a routing decision to carry a tenant boundary.
type natsEnvelope struct {
	EventID   string          `json:"event_id"`
	EventType string          `json:"event_type"`
	OrgID     string          `json:"org_id"`
	Source    string          `json:"source"`
	Payload   json.RawMessage `json:"payload"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

func (s *NATSSink) subject(d Delivery) (string, error) {
	if err := validSubjectToken(d.OrgID); err != nil {
		return "", fmt.Errorf("event %s org id: %w", d.EventID, err)
	}
	if err := validSubjectSuffix(d.EventType); err != nil {
		return "", fmt.Errorf("event %s type: %w", d.EventID, err)
	}
	return s.prefix + "." + d.OrgID + "." + d.EventType, nil
}

// validSubjectToken checks a value that must occupy exactly ONE subject token:
// the platform prefix, and the tenant. See the header for why a dot is fatal
// here and merely structural in the type.
func validSubjectToken(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	if strings.Contains(s, ".") {
		return fmt.Errorf("must occupy one subject token, so it must not contain a separator (got %q)", s)
	}
	return validSubjectChars(s)
}

// validSubjectSuffix checks a value that may span SEVERAL tokens: the event
// type, whose dots are the hierarchy a consumer subscribes into.
func validSubjectSuffix(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return fmt.Errorf("must not contain an empty token, which shifts every token after it (got %q)", s)
	}
	return validSubjectChars(s)
}

// validSubjectChars is what both halves share: no wildcard, no whitespace, no
// control character.
func validSubjectChars(s string) error {
	if strings.ContainsAny(s, "*>") {
		return fmt.Errorf("must not contain a wildcard (got %q)", s)
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("must not contain whitespace (got %q)", s)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("must not contain a control character (got %q)", s)
		}
	}
	return nil
}
