package access

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/agentic"
	"github.com/openidx/openidx/internal/agentic/provider"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// agenticMode is how far the platform may act on a device without a person.
// The words are the self-heal loop's: off does nothing, observe records what
// it would have done, tier0 applies fixes that only restart or collect, tier1
// adds fixes that change the agent's software.
type agenticMode string

const (
	modeOff     agenticMode = "off"
	modeObserve agenticMode = "observe"
	modeTier0   agenticMode = "tier0"
	modeTier1   agenticMode = "tier1"
)

func parseAgenticMode(s string) (agenticMode, bool) {
	m := agenticMode(strings.ToLower(strings.TrimSpace(s)))
	switch m {
	case modeOff, modeObserve, modeTier0, modeTier1:
		return m, true
	}
	return "", false
}

func (m agenticMode) rank() int {
	switch m {
	case modeObserve:
		return 1
	case modeTier0:
		return 2
	case modeTier1:
		return 3
	}
	return 0
}

// cappedBy returns the lower of the organization's mode and the deployment's
// cap. An empty or unknown cap does not cap.
func (m agenticMode) cappedBy(cap string) agenticMode {
	c, ok := parseAgenticMode(cap)
	if !ok || c.rank() >= m.rank() {
		return m
	}
	return c
}

// agenticSettings is one organization's autonomy and assistant setting.
type agenticSettings struct {
	// Mode is what the organization chose.
	Mode       agenticMode `json:"mode"`
	KillSwitch bool        `json:"kill_switch"`
	// Effective is Mode after the deployment's cap.
	Effective agenticMode `json:"effective_mode"`
	UpdatedAt *time.Time  `json:"updated_at,omitempty"`

	// The assistant's model. Provider "none" means no model is called and the
	// assistant answers in the rule engine's own words.
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	BaseURL      string `json:"base_url"`
	Redaction    string `json:"redaction"`
	ToolsEnabled bool   `json:"tools_enabled"`
	// HasAPIKey says a key is stored; the key itself is never returned.
	HasAPIKey      bool       `json:"has_api_key"`
	CloudConsentAt *time.Time `json:"cloud_consent_at,omitempty"`

	apiKeyEnc string
}

func defaultAgenticSettings() agenticSettings {
	return agenticSettings{Mode: modeObserve, Provider: provider.KindNone, Redaction: "mask", ToolsEnabled: true}
}

// loadAgenticSettings reads the tenant's setting; a tenant that never chose
// gets observe, no model and the kill switch off. A read that fails also gets
// observe: the platform records but does not act when it cannot tell.
func loadAgenticSettings(ctx context.Context, db *database.PostgresDB, orgID, cap string) (agenticSettings, error) {
	s := defaultAgenticSettings()
	var mode string
	var at time.Time
	err := db.Pool.QueryRow(ctx, `
		SELECT mode, kill_switch, updated_at, provider, model, base_url, redaction,
		       tools_enabled, api_key_enc, cloud_consent_at
		  FROM org_agentic_settings WHERE org_id = $1`, orgID).
		Scan(&mode, &s.KillSwitch, &at, &s.Provider, &s.Model, &s.BaseURL, &s.Redaction,
			&s.ToolsEnabled, &s.apiKeyEnc, &s.CloudConsentAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		s = defaultAgenticSettings()
		s.Effective = modeObserve.cappedBy(cap)
		return s, err
	default:
		if m, ok := parseAgenticMode(mode); ok {
			s.Mode = m
		}
		s.UpdatedAt = &at
		s.HasAPIKey = s.apiKeyEnc != ""
	}
	s.Effective = s.Mode.cappedBy(cap)
	return s, nil
}

func (s *Service) denyPrivateModelHosts() bool {
	return s.config != nil && s.config.AgenticDenyPrivateModelHosts
}

func (s *Service) agenticCap() string {
	if s.config == nil {
		return ""
	}
	return s.config.AgenticMode
}

func (s *Service) handleGetAgenticSettings(c *gin.Context) {
	ctx := c.Request.Context()
	set, err := loadAgenticSettings(ctx, s.db, orgIDFrom(ctx), s.agenticCap())
	if err != nil {
		s.logger.Error("load agentic settings failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load the settings"})
		return
	}
	c.JSON(http.StatusOK, set)
}

// handlePutAgenticSettings changes the settings; any field may be omitted to
// leave it as it is. Every change is audited (never the key); the kill switch
// has its own event so "who stopped it" is one search.
func (s *Service) handlePutAgenticSettings(c *gin.Context) {
	var body struct {
		Mode         *string `json:"mode"`
		KillSwitch   *bool   `json:"kill_switch"`
		Provider     *string `json:"provider"`
		Model        *string `json:"model"`
		BaseURL      *string `json:"base_url"`
		Redaction    *string `json:"redaction"`
		ToolsEnabled *bool   `json:"tools_enabled"`
		// APIKey replaces the stored key; "" removes it.
		APIKey *string `json:"api_key"`
		// CloudConsent must be true to choose a model in someone else's cloud.
		CloudConsent *bool `json:"cloud_consent"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unreadable body"})
		return
	}
	ctx := c.Request.Context()
	orgID := orgIDFrom(ctx)
	cur, err := loadAgenticSettings(ctx, s.db, orgID, s.agenticCap())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load the settings"})
		return
	}
	next := cur
	bad := func(msg string) { c.JSON(http.StatusBadRequest, gin.H{"error": msg}) }
	if body.Mode != nil {
		m, ok := parseAgenticMode(*body.Mode)
		if !ok {
			bad("mode must be off, observe, tier0 or tier1")
			return
		}
		next.Mode = m
	}
	if body.KillSwitch != nil {
		next.KillSwitch = *body.KillSwitch
	}
	if body.Provider != nil {
		if !provider.ValidKind(*body.Provider) {
			bad("provider must be none, anthropic or openai_compat")
			return
		}
		next.Provider = *body.Provider
	}
	if body.Redaction != nil {
		switch *body.Redaction {
		case "off", "mask", "strict":
			next.Redaction = *body.Redaction
		default:
			bad("redaction must be off, mask or strict")
			return
		}
	}
	if body.Model != nil {
		if len(*body.Model) > 128 {
			bad("model name too long")
			return
		}
		next.Model = strings.TrimSpace(*body.Model)
	}
	if body.BaseURL != nil {
		u := strings.TrimSpace(*body.BaseURL)
		if u != "" && (len(u) > 512 || provider.CheckBaseURL(u, s.denyPrivateModelHosts()) != nil) {
			bad("base_url must be an http(s) address such as http://ollama.internal:11434/v1 (not link-local or unspecified)")
			return
		}
		next.BaseURL = u
	}
	if body.ToolsEnabled != nil {
		next.ToolsEnabled = *body.ToolsEnabled
	}
	if body.APIKey != nil {
		key := strings.TrimSpace(*body.APIKey)
		if len(key) > 512 {
			bad("api_key too long")
			return
		}
		if key == "" {
			next.apiKeyEnc = ""
		} else {
			enc, err := s.agenticCipher().Encrypt(key)
			if err != nil {
				s.logger.Error("encrypt assistant api key failed", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to protect the key"})
				return
			}
			next.apiKeyEnc = enc
		}
	}

	// A stored key belongs to the endpoint it was stored for. Pointing the
	// assistant at a different provider or address must bring its own key, or
	// the old one would be sent to the new place.
	if (next.Provider != cur.Provider || next.BaseURL != cur.BaseURL) && body.APIKey == nil {
		next.apiKeyEnc = ""
	}

	actor := c.GetString("user_id")
	var consentBy interface{}
	if _, perr := uuid.Parse(actor); perr == nil {
		consentBy = actor
	}
	switch next.Provider {
	case provider.KindAnthropic:
		// The cloud model is always reached at Anthropic's own address. An
		// address kept from an earlier choice would never be used, and must
		// not be able to become the place a key is sent.
		next.BaseURL = ""
		if next.Redaction == "off" {
			bad("masking cannot be off for a model in someone else's cloud")
			return
		}
		if next.CloudConsentAt == nil {
			if body.CloudConsent == nil || !*body.CloudConsent {
				bad("choosing a cloud model sends masked conversation text to Anthropic; confirm with cloud_consent: true")
				return
			}
			now := time.Now().UTC()
			next.CloudConsentAt = &now
		}
		if next.apiKeyEnc == "" && (s.config == nil || s.config.AnthropicAPIKey == "") {
			bad("no API key: store one for this organization or set ANTHROPIC_API_KEY")
			return
		}
	case provider.KindOpenAICompat:
		next.CloudConsentAt = nil
		if next.BaseURL == "" && (s.config == nil || s.config.AIBaseURL == "") {
			bad("base_url is required for a model you run yourself")
			return
		}
		if next.Model == "" && (s.config == nil || s.config.AIModel == "") {
			bad("model is required for a model you run yourself")
			return
		}
	default:
		next.CloudConsentAt = nil
	}

	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO org_agentic_settings
		       (org_id, mode, kill_switch, updated_by, updated_at, provider, model, base_url, redaction,
		        tools_enabled, api_key_enc, cloud_consent_at, cloud_consent_by)
		VALUES ($1, $2, $3, $4::uuid, NOW(), $5, $6, $7, $8, $9, $10, $11, $12::uuid)
		ON CONFLICT (org_id) DO UPDATE
		   SET mode = EXCLUDED.mode, kill_switch = EXCLUDED.kill_switch,
		       updated_by = EXCLUDED.updated_by, updated_at = NOW(),
		       provider = EXCLUDED.provider, model = EXCLUDED.model, base_url = EXCLUDED.base_url,
		       redaction = EXCLUDED.redaction, tools_enabled = EXCLUDED.tools_enabled,
		       api_key_enc = EXCLUDED.api_key_enc,
		       cloud_consent_at = EXCLUDED.cloud_consent_at,
		       cloud_consent_by = CASE WHEN EXCLUDED.cloud_consent_at IS NULL THEN NULL
		                               WHEN org_agentic_settings.cloud_consent_at IS NULL THEN EXCLUDED.cloud_consent_by
		                               ELSE org_agentic_settings.cloud_consent_by END`,
		orgID, string(next.Mode), next.KillSwitch, consentBy, next.Provider, next.Model, next.BaseURL,
		next.Redaction, next.ToolsEnabled, next.apiKeyEnc, next.CloudConsentAt, consentBy); err != nil {
		s.logger.Error("save agentic settings failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save the settings"})
		return
	}
	if next.Mode != cur.Mode {
		s.auditAgentic(c, "agentic.settings.updated", "mode "+string(cur.Mode)+" -> "+string(next.Mode))
	}
	if next.Provider != cur.Provider || next.Model != cur.Model || next.Redaction != cur.Redaction ||
		next.BaseURL != cur.BaseURL || next.apiKeyEnc != cur.apiKeyEnc {
		s.auditAgentic(c, "agentic.provider.updated",
			"provider "+cur.Provider+" -> "+next.Provider+", model "+next.Model+", redaction "+next.Redaction+
				", key "+map[bool]string{true: "set", false: "none"}[next.apiKeyEnc != ""])
	}
	if next.KillSwitch != cur.KillSwitch {
		state := "off"
		if next.KillSwitch {
			state = "on"
		}
		s.auditAgentic(c, "agentic.killswitch.set", "kill switch "+state)
	}
	next.HasAPIKey = next.apiKeyEnc != ""
	next.Effective = next.Mode.cappedBy(s.agenticCap())
	now := time.Now().UTC()
	next.UpdatedAt = &now
	c.JSON(http.StatusOK, next)
}

// agenticCipher seals the assistant's API key with the service's key, or not
// at all when the deployment sets none (as for every other stored secret).
func (s *Service) agenticCipher() *secretcrypt.Cipher {
	if s.idpCipher != nil {
		return s.idpCipher
	}
	return secretcrypt.NewNoop()
}

// agenticProvider builds the model backend an organization chose. The error is
// provider.ErrNone when it chose none; callers then answer from the rules.
func (s *Service) agenticProvider(set agenticSettings) (agentic.Provider, error) {
	cfg := provider.Config{Kind: set.Provider, Model: set.Model, BaseURL: set.BaseURL, NoTools: !set.ToolsEnabled,
		DenyPrivate: s.denyPrivateModelHosts()}
	if set.apiKeyEnc != "" {
		key, err := s.agenticCipher().Decrypt(set.apiKeyEnc)
		if err != nil {
			return nil, errors.New("the stored API key cannot be read")
		}
		cfg.APIKey = key
	}
	if s.config != nil {
		if cfg.APIKey == "" && set.Provider == provider.KindAnthropic {
			cfg.APIKey = s.config.AnthropicAPIKey
		}
		if set.Provider == provider.KindOpenAICompat {
			if cfg.BaseURL == "" {
				cfg.BaseURL = s.config.AIBaseURL
			}
			if cfg.Model == "" {
				cfg.Model = s.config.AIModel
			}
		}
	}
	return provider.New(cfg)
}

func (s *Service) auditAgentic(c *gin.Context, action, detail string) {
	s.logAuditEvent(c, action, orgIDFrom(c.Request.Context()), "organization",
		map[string]interface{}{"detail": detail})
}

// agenticActionRecord is one ledger row as the console lists it.
type agenticActionRecord struct {
	ID           string    `json:"id"`
	AgentID      string    `json:"agent_id"`
	Action       string    `json:"action"`
	Cause        string    `json:"cause"`
	Mode         string    `json:"mode"`
	Outcome      string    `json:"outcome"`
	Reason       string    `json:"reason,omitempty"`
	CommandID    string    `json:"command_id,omitempty"`
	DiagnosticID string    `json:"diagnostic_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// handleListAgenticActions lists the ledger, newest first, optionally for one
// device.
func (s *Service) handleListAgenticActions(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, agent_id, action, cause, mode, outcome, reason,
		       COALESCE(command_id::text, ''), COALESCE(diagnostic_id::text, ''), created_at
		  FROM agentic_actions
		 WHERE org_id = $1 AND ($2 = '' OR agent_id = $2)
		 ORDER BY created_at DESC, id DESC LIMIT 100`,
		orgIDFrom(ctx), c.Query("agent_id"))
	if err != nil {
		s.logger.Error("list agentic actions failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list the actions"})
		return
	}
	defer rows.Close()
	out := []agenticActionRecord{}
	for rows.Next() {
		var r agenticActionRecord
		if err := rows.Scan(&r.ID, &r.AgentID, &r.Action, &r.Cause, &r.Mode, &r.Outcome,
			&r.Reason, &r.CommandID, &r.DiagnosticID, &r.CreatedAt); err != nil {
			s.logger.Error("scan agentic action failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list the actions"})
			return
		}
		out = append(out, r)
	}
	c.JSON(http.StatusOK, gin.H{"actions": out})
}
