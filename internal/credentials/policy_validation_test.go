package credentials

import (
	"errors"
	"testing"

	"go.uber.org/zap"
)

// validConfigs are minimal connector_config maps that satisfy each connector's parser.
func validConfigs() map[string]map[string]any {
	return map[string]map[string]any{
		"directory": {"directory_id": "d1", "username": "svc"},
		"ssh": {
			"host": "h", "username": "svc", "admin_secret_id": "s",
			"admin_username": "root", "host_key": "ssh-ed25519 AAAA",
		},
		"ssh_key": {
			"host": "h", "username": "svc", "admin_secret_id": "s",
			"admin_username": "root", "host_key": "ssh-ed25519 AAAA",
		},
		"postgres": {
			"host": "h", "dbname": "db", "admin_secret_id": "s",
			"admin_username": "admin", "target_role": "svc",
		},
		"mysql": {
			"host": "h", "admin_secret_id": "s",
			"admin_username": "root", "target_user": "svc",
		},
		"generate_only": {},
	}
}

// testService builds a Service with every connector registered but no db/vault —
// validatePolicyInput touches neither.
func testService(t *testing.T) *Service {
	t.Helper()
	rotators := []Rotator{
		NewGenerateOnlyRotator(),
		NewSSHRotator(nil),
		NewSSHKeyRotator(nil),
		NewPostgresRotator(nil),
		NewMySQLRotator(nil),
		&directoryRotator{}, // dir is unused by ValidateConfig
	}
	return NewService(nil, nil, rotators, nil, 24, zap.NewNop())
}

func TestValidatePolicyInput_AllRegisteredTypesAccepted(t *testing.T) {
	s := testService(t)
	for typ, cfg := range validConfigs() {
		in := PolicyInput{ConnectorType: typ, ConnectorConfig: cfg, IntervalSeconds: 3600}
		if err := s.validatePolicyInput(in); err != nil {
			t.Errorf("type %q with valid config: unexpected error: %v", typ, err)
		}
	}
}

func TestValidatePolicyInput_MissingRequiredFieldRejected(t *testing.T) {
	s := testService(t)
	// For each config-bearing type, drop one required field → expect ErrInvalidPolicy.
	cases := map[string]string{
		"directory": "directory_id",
		"ssh":       "host",
		"ssh_key":   "admin_secret_id",
		"postgres":  "target_role",
		"mysql":     "target_user",
	}
	all := validConfigs()
	for typ, drop := range cases {
		cfg := map[string]any{}
		for k, v := range all[typ] {
			if k != drop {
				cfg[k] = v
			}
		}
		in := PolicyInput{ConnectorType: typ, ConnectorConfig: cfg, IntervalSeconds: 3600}
		err := s.validatePolicyInput(in)
		if !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("type %q missing %q: want ErrInvalidPolicy, got %v", typ, drop, err)
		}
	}
}

func TestValidatePolicyInput_UnknownTypeRejected(t *testing.T) {
	s := testService(t)
	err := s.validatePolicyInput(PolicyInput{ConnectorType: "nope", IntervalSeconds: 0})
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown type: want ErrInvalidPolicy, got %v", err)
	}
}

func TestValidatePolicyInput_NegativeIntervalRejected(t *testing.T) {
	s := testService(t)
	in := PolicyInput{ConnectorType: "generate_only", ConnectorConfig: map[string]any{}, IntervalSeconds: -1}
	if !errors.Is(s.validatePolicyInput(in), ErrInvalidPolicy) {
		t.Fatal("negative interval: want ErrInvalidPolicy")
	}
}
