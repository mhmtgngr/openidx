package access

import (
	"encoding/json"
	"os"
)

// readAgentSupportCodes loads the support codes the agent's own encoder wrote.
func readAgentSupportCodes() (map[string][]string, error) {
	raw, err := os.ReadFile("../../agent/internal/doctor/testdata/support_codes.json")
	if err != nil {
		return nil, err
	}
	var out map[string][]string
	return out, json.Unmarshal(raw, &out)
}
