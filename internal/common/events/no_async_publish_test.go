package events

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// THE GUARD THAT KEEPS THE SINK'S CONTRACT BUYABLE ONLY AT ITS PRICE.
//
// Sink.Publish promises the broker has accepted the event by the time it
// returns nil, and the relay deletes the outbox row on that nil. Two of the
// NATS client's three publish calls return before the broker has the message --
// measured, by counting what the stream held at the instant the call returned:
//
//	nc.Publish       33 of 200      js.PublishAsync  60 of 200      js.Publish  200 of 200
//
// The wrong one is also sixty times faster, which is exactly why this guard
// exists. `js.Publish` costs 163us per event against 0.5us, and a profile will
// point at it one day. Swapping it is not an optimisation; it is a silent
// downgrade from at-least-once to at-most-once, and the only thing that would
// change in CI is that this test goes red.
//
// AST rather than grep, because the file's own comment block names both
// forbidden calls in order to explain them. A guard that cannot tell a call
// from a sentence would have to be written around, and the way people write
// around it is by not writing the sentence.
func TestTheNATSSinkPublishesSynchronously(t *testing.T) {
	const file = "nats_sink.go"

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, 0) // 0: comments discarded
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	forbidden := map[string]string{
		"PublishAsync":    "returns a future; the ack arrives later, so a nil return says nothing about the broker having the event",
		"PublishMsgAsync": "same as PublishAsync",
	}

	var sawSyncPublish bool
	var findings []string

	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		recv := receiverName(sel.X)

		if why, bad := forbidden[name]; bad {
			findings = append(findings, "%s calls "+recv+"."+name+": "+why)
		}
		// The core connection's Publish is the fire-and-forget one. Reached
		// through a *nats.Conn it is buffered client-side and returns before
		// anything has left the process.
		if name == "Publish" && strings.Contains(recv, "nc") {
			findings = append(findings, "%s calls "+recv+".Publish: the CORE publish is buffered client-side and returns before the broker has the message")
		}
		if name == "Publish" && (strings.Contains(recv, "js") || strings.Contains(recv, "s.js")) {
			sawSyncPublish = true
		}
		return true
	})

	for _, f := range findings {
		t.Errorf(f+"\nSink.Publish must return only once the broker has ACCEPTED the event: the relay deletes the outbox row on a nil return, so anything faster loses events with nothing visible anywhere.", file)
	}

	// Vacuity, and the failure that would otherwise be silent: a file that had
	// stopped publishing at all would pass every assertion above.
	if !sawSyncPublish {
		t.Errorf("%s holds no js.Publish call; either the sink stopped publishing or it now reaches the broker some way this guard cannot see", file)
	}
}

func receiverName(x ast.Expr) string {
	switch v := x.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return receiverName(v.X) + "." + v.Sel.Name
	default:
		return ""
	}
}

// The subject is assembled from values that arrive from outside, and `.`, `*`
// and `>` are structure rather than text in a NATS subject. An event type of
// "user.>" published under a tenant's prefix is a subject a narrowly permitted
// subscriber was never meant to receive, so the check is on the way in.
func TestASubjectTokenCannotCarryStructure(t *testing.T) {
	s := &NATSSink{prefix: "openidx"}

	t.Run("an ordinary event goes where it says", func(t *testing.T) {
		got, err := s.subject(Delivery{OrgID: "org-1", EventType: "user_created", EventID: "e1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := "openidx.org-1.user_created"; got != want {
			t.Errorf("subject = %q, want %q", got, want)
		}
	})

	for _, tc := range []struct {
		name  string
		d     Delivery
		about string
	}{
		{"wildcard in the event type", Delivery{OrgID: "org-1", EventType: "user.>", EventID: "e"}, "publishes under a subject tree instead of a leaf"},
		{"single-token wildcard", Delivery{OrgID: "org-1", EventType: "user.*", EventID: "e"}, "same, one level"},
		{"separator in the org id", Delivery{OrgID: "org-1.admin", EventType: "user_created", EventID: "e"}, "moves the event into another tenant's position"},
		{"wildcard as the org id", Delivery{OrgID: ">", EventType: "user_created", EventID: "e"}, "the whole tree"},
		{"empty org id", Delivery{OrgID: "", EventType: "user_created", EventID: "e"}, "collapses a token and shifts every one after it"},
		{"empty event type", Delivery{OrgID: "org-1", EventType: "", EventID: "e"}, "same"},
		{"whitespace", Delivery{OrgID: "org 1", EventType: "user_created", EventID: "e"}, "a subject is a wire token"},
		{"newline", Delivery{OrgID: "org-1", EventType: "user\ncreated", EventID: "e"}, "and the server is not the only thing that reads it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.subject(tc.d)
			if err == nil {
				t.Errorf("subject(%+v) = %q with no error; %s", tc.d, got, tc.about)
			}
		})
	}
}
