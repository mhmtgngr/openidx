package provider

import (
	"errors"
	"strings"

	"github.com/openidx/openidx/internal/agentic"
)

// Kinds an organization may choose.
const (
	KindNone         = "none"
	KindAnthropic    = "anthropic"
	KindOpenAICompat = "openai_compat"
)

// ValidKind says whether s names a provider.
func ValidKind(s string) bool {
	return s == KindNone || s == KindAnthropic || s == KindOpenAICompat
}

// Config is an organization's provider choice, with secrets already decrypted.
type Config struct {
	Kind    string
	Model   string
	BaseURL string
	APIKey  string
	NoTools bool
}

// ErrNone means no model is configured; callers answer from the rules.
var ErrNone = errors.New("no model is configured")

// New builds the provider a Config names.
func New(c Config) (agentic.Provider, error) {
	switch strings.ToLower(c.Kind) {
	case KindAnthropic:
		return NewAnthropic(AnthropicConfig{APIKey: c.APIKey, Model: c.Model})
	case KindOpenAICompat:
		return NewOpenAI(OpenAIConfig{BaseURL: c.BaseURL, Model: c.Model, APIKey: c.APIKey, NoTools: c.NoTools})
	}
	return nil, ErrNone
}
