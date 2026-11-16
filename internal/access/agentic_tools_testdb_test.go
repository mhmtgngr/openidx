package access

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/agentic"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// An assistant asked about one person's devices sees those and no others, and
// says what the rule engine says.
func TestAssistantToolsAreScopedToThePerson(t *testing.T) {
	h, ada, bo := newDiagnoseHarness(t, "assist-tools-org")
	h.agent("ada-pc", ada, "active", "compliant", "1 minute", "degraded")
	h.agent("bo-pc", bo, "active", "compliant", "1 minute", "")
	s := h.svc
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: h.orgID})
	reg := s.agenticRegistry()

	p := agentic.Principal{OrgID: h.orgID, UserID: ada, DeviceIDs: []string{"ada-pc"}}
	call := func(p agentic.Principal, tool, input string) agentic.Result {
		return reg.Dispatch(ctx, p, "observe", agentic.RedactMask,
			agentic.Block{Type: agentic.BlockToolUse, Name: tool, Input: json.RawMessage(input)}, nil)
	}

	list := call(p, "list_my_devices", `{}`)
	if list.IsError || !strings.Contains(list.Content, "ada-pc") || strings.Contains(list.Content, "bo-pc") {
		t.Errorf("list_my_devices = %+v", list)
	}
	own := call(p, "diagnose_my_device", `{}`)
	if own.IsError || !strings.Contains(own.Content, "TUNNEL_DOWN") {
		t.Errorf("diagnose_my_device = %+v", own)
	}
	if other := call(p, "diagnose_my_device", `{"agent_id":"bo-pc"}`); !other.IsError {
		t.Errorf("a stranger's device was diagnosed: %+v", other)
	}
	if ops := call(p, "recent_automatic_actions", `{}`); !ops.IsError {
		t.Errorf("a user reached an operator tool: %+v", ops)
	}
	op := agentic.Principal{OrgID: h.orgID, UserID: ada, Operator: true}
	if ops := call(op, "recent_automatic_actions", `{}`); ops.IsError {
		t.Errorf("an operator was refused: %+v", ops)
	}
}
