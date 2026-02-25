// Package admin provides GenAI attack detection for prompt injection and data exfiltration
// This module implements security analysis for AI/LLM interactions to detect and prevent
// malicious prompt injection attempts and data exfiltration patterns.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// GenAIAttackType represents the type of GenAI attack detected
type GenAIAttackType string

const (
	// AttackPromptInjection indicates prompt injection attempts
	AttackPromptInjection GenAIAttackType = "prompt_injection"
	// AttackDataExfiltration indicates data exfiltration attempts
	AttackDataExfiltration GenAIAttackType = "data_exfiltration"
	// AttackJailbreak indicates jailbreak attempts
	AttackJailbreak GenAIAttackType = "jailbreak"
	// AttackTokenManipulation indicates token usage manipulation
	AttackTokenManipulation GenAIAttackType = "token_manipulation"
	// AttackModelDistillation indicates model distillation attempts
	AttackModelDistillation GenAIAttackType = "model_distillation"
)

// GenAIAttackSeverity represents the severity level of a detected attack
type GenAIAttackSeverity string

const (
	SeverityLow      GenAIAttackSeverity = "low"
	SeverityMedium   GenAIAttackSeverity = "medium"
	SeverityHigh     GenAIAttackSeverity = "high"
	SeverityCritical GenAIAttackSeverity = "critical"
)

// GenAIAttackRequest represents an incoming AI request to be analyzed
type GenAIAttackRequest struct {
	RequestID    string            `json:"request_id"`
	UserID       string            `json:"user_id"`
	SessionID    string            `json:"session_id"`
	Prompt       string            `json:"prompt"`
	AgentID      string            `json:"agent_id"`
	Context      string            `json:"context"`
	Metadata     map[string]string `json:"metadata"`
	Timestamp    time.Time         `json:"timestamp"`
	IPAddress    string            `json:"ip_address"`
	UserAgent    string            `json:"user_agent"`
	PreviousTurns int              `json:"previous_turns"`
}

// GenAIAttackDetectionResult represents the result of an attack analysis
type GenAIAttackDetectionResult struct {
	RequestID        string               `json:"request_id"`
	AttackDetected   bool                 `json:"attack_detected"`
	AttackTypes      []GenAIAttackType    `json:"attack_types"`
	Severity         GenAIAttackSeverity  `json:"severity"`
	Confidence       float64              `json:"confidence"`
	Reasons          []string             `json:"reasons"`
	MatchedPatterns  []string             `json:"matched_patterns"`
	SuggestedActions []string             `json:"suggested_actions"`
	AnalyzedAt       time.Time            `json:"analyzed_at"`
	RiskScore        float64              `json:"risk_score"`
}

// GenAISecurityRule represents a custom security rule for attack detection
type GenAISecurityRule struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	AttackType      GenAIAttackType `json:"attack_type"`
	Enabled         bool            `json:"enabled"`
	Patterns        []string        `json:"patterns"`
	Keywords        []string        `json:"keywords"`
	Action          string          `json:"action"`
	Severity        GenAIAttackSeverity `json:"severity"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// GenAIAttackMetrics represents attack detection metrics
type GenAIAttackMetrics struct {
	TotalRequests        int64                    `json:"total_requests"`
	AttacksDetected      int64                    `json:"attacks_detected"`
	AttacksByType        map[GenAIAttackType]int64 `json:"attacks_by_type"`
	AttacksBySeverity    map[GenAIAttackSeverity]int64 `json:"attacks_by_severity"`
	TopAttackSources     []AttackSource           `json:"top_attack_sources"`
	AverageResponseTime  float64                  `json:"average_response_time_ms"`
	FalsePositiveRate    float64                  `json:"false_positive_rate"`
	TimeRange            string                   `json:"time_range"`
	GeneratedAt          time.Time                `json:"generated_at"`
}

// AttackSource represents a source of attacks
type AttackSource struct {
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address"`
	Count     int64  `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
}

// GenAIRequestPattern represents an analyzed request pattern
type GenAIRequestPattern struct {
	UserID           string    `json:"user_id"`
	AgentID          string    `json:"agent_id"`
	RequestFrequency int       `json:"request_frequency"`
	AveragePromptLength float64 `json:"average_prompt_length"`
	CommonPatterns   []string  `json:"common_patterns"`
	RiskScore        float64   `json:"risk_score"`
	LastAnalyzed     time.Time `json:"last_analyzed"`
}

// genaiAttackDetectionService handles GenAI attack detection
type genaiAttackDetectionService struct {
	db     *database.PostgresDB
	logger *zap.Logger
}

// DetectPromptInjection analyzes a prompt for injection attempts
func (s *genaiAttackDetectionService) DetectPromptInjection(ctx context.Context, req *GenAIAttackRequest) *GenAIAttackDetectionResult {
	result := &GenAIAttackDetectionResult{
		RequestID:      req.RequestID,
		AttackDetected: false,
		AttackTypes:    []GenAIAttackType{},
		Severity:       SeverityLow,
		Confidence:     0,
		Reasons:        []string{},
		MatchedPatterns: []string{},
		SuggestedActions: []string{},
		AnalyzedAt:     time.Now(),
		RiskScore:      0,
	}

	riskScore := 0.0

	// Known prompt injection patterns
	injectionPatterns := []struct {
		pattern  string
		severity GenAIAttackSeverity
		weight   float64
		reason   string
	}{
		{`(?i)ignore\s+(all\s+)?(previous|above|earlier)\s+(instructions?|prompts?|commands?)`, SeverityHigh, 0.8, "Attempt to ignore previous instructions"},
		{`(?i)forget\s+(everything|all|the\s+)(previous|above|earlier)`, SeverityHigh, 0.8, "Attempt to reset context"},
		{`(?i)act\s+as\s+a\s+different`, SeverityMedium, 0.5, "Role manipulation attempt"},
		{`(?i)you\s+are\s+now\s+(a\s+)?(hacker|attacker|criminal)`, SeverityHigh, 0.7, "Malicious role assignment"},
		{`(?i)(disregard|ignore|override)\s+the\s+(rules|guidelines|constraints)`, SeverityHigh, 0.8, "Attempting to bypass rules"},
		{`(?i)new\s+(role|persona|character)\s*:`, SeverityMedium, 0.4, "Role injection attempt"},
		{`(?i)system\s*:\s*ignore`, SeverityCritical, 0.9, "System command injection"},
		{`(?i)(<\|(.*?)\|>|<<\[(.*?)\]>>|\[\[(.*?)\]\])`, SeverityHigh, 0.6, "Format string injection"},
		{`(?i)(dAN|DAN)\s*(mode|activation)`, SeverityHigh, 0.7, "DAN/jailbreak attempt"},
		{`(?i)(developer|admin|root)\s+mode`, SeverityMedium, 0.5, "Privilege escalation attempt"},
		{`(?i)translate\s+(everything|this)\s+to\s+(javascript|python|code)`, SeverityMedium, 0.5, "Code injection via translation"},
		{`(?i)(print|output|return)\s+(everything|all\s+data|internal\s+info)`, SeverityHigh, 0.7, "Data exfiltration via output"},
		{`(?i)JSON\s*(format|output)\s*:\s*\{`, SeverityMedium, 0.4, "Structured data extraction"},
		{`(?i)(previous|context|history)\s+(above|before)`, SeverityLow, 0.2, "Context manipulation"},
	}

	for _, p := range injectionPatterns {
		re, err := regexp.Compile(p.pattern)
		if err != nil {
			continue
		}
		if re.MatchString(req.Prompt) {
			result.AttackDetected = true
			result.AttackTypes = append(result.AttackTypes, AttackPromptInjection)
			result.MatchedPatterns = append(result.MatchedPatterns, p.pattern)
			result.Reasons = append(result.Reasons, p.reason)
			riskScore += p.weight

			if result.Severity == SeverityLow || compareSeverity(p.severity, result.Severity) > 0 {
				result.Severity = p.severity
			}
		}
	}

	// Check for jailbreak patterns
	jailbreakPatterns := []string{
		`(?i)(do|say|tell)\s+(anything|whatever\s+i\s+want)`,
		`(?i)no\s+(limits|restrictions|rules)`,
		`(?i)(unrestricted|uncensored|unfiltered)`,
		`(?i)(bypass|override)\s+(safety|security|filters)`,
		`(?i)(hypothetical|theoretical)\s+scenario`,
		`(?i)role[- ]?play\s+(as|where)`,
	}

	for _, pattern := range jailbreakPatterns {
		if matched, _ := regexp.MatchString(pattern, req.Prompt); matched {
			result.AttackDetected = true
			result.AttackTypes = append(result.AttackTypes, AttackJailbreak)
			result.Reasons = append(result.Reasons, "Jailbreak pattern detected")
			riskScore += 0.5
			break
		}
	}

	// Check for data exfiltration patterns
	exfilPatterns := []string{
		`(?i)(dump|export|extract|leak)\s+(all\s+)?(data|database|records|users)`,
		`(?i)(send|transmit|forward)\s+(everything|all\s+data)\s+to`,
		`(?i)base64\s*(encode|decode)\s+(everything|all)`,
		`(?i)(hidden|internal|secret)\s+(prompt|instruction|system)`,
	}

	for _, pattern := range exfilPatterns {
		if matched, _ := regexp.MatchString(pattern, req.Prompt); matched {
			result.AttackDetected = true
			result.AttackTypes = append(result.AttackTypes, AttackDataExfiltration)
			result.Reasons = append(result.Reasons, "Data exfiltration pattern detected")
			riskScore += 0.7
			break
		}
	}

	// Calculate final confidence and risk score
	if result.AttackDetected {
		result.Confidence = minFloat(riskScore, 1.0)
		result.RiskScore = riskScore * 100

		// Add suggested actions based on severity
		switch result.Severity {
		case SeverityCritical, SeverityHigh:
			result.SuggestedActions = []string{
				"block_request",
				"alert_admin",
				"flag_user",
				"terminate_session",
			}
		case SeverityMedium:
			result.SuggestedActions = []string{
				"sanitize_prompt",
				"alert_admin",
				"log_incident",
			}
		case SeverityLow:
			result.SuggestedActions = []string{
				"monitor",
				"log_incident",
			}
		}
	}

	return result
}

// DetectDataExfiltration analyzes responses for data exfiltration
func (s *genaiAttackDetectionService) DetectDataExfiltration(ctx context.Context, response string, prompt string) *GenAIAttackDetectionResult {
	result := &GenAIAttackDetectionResult{
		RequestID:      uuid.New().String(),
		AttackDetected: false,
		AttackTypes:    []GenAIAttackType{},
		Severity:       SeverityLow,
		Confidence:     0,
		AnalyzedAt:     time.Now(),
	}

	riskScore := 0.0

	// Check for structured data dumps
	if len(response) > 5000 {
		// Very long response might be data dump
		riskScore += 0.3
		result.Reasons = append(result.Reasons, "Unusually long response")
	}

	// Check for JSON/CSV dumps
	if strings.HasPrefix(strings.TrimSpace(response), "{") ||
		strings.HasPrefix(strings.TrimSpace(response), "[") {
		// Count number of objects
		openBraces := strings.Count(response, "{")
		if openBraces > 10 {
			result.AttackDetected = true
			result.AttackTypes = append(result.AttackTypes, AttackDataExfiltration)
			result.Reasons = append(result.Reasons, "Multiple JSON objects detected")
			riskScore += 0.5
		}
	}

	// Check for email/phone patterns in bulk
	emailRegex := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	emails := emailRegex.FindAllString(response, -1)
	if len(emails) > 5 {
		result.AttackDetected = true
		result.AttackTypes = append(result.AttackTypes, AttackDataExfiltration)
		result.Reasons = append(result.Reasons, fmt.Sprintf("Bulk email addresses detected: %d", len(emails)))
		riskScore += 0.6
	}

	// Check for credit card patterns
	ccRegex := regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`)
	ccNumbers := ccRegex.FindAllString(response, -1)
	if len(ccNumbers) > 3 {
		result.AttackDetected = true
		result.AttackTypes = append(result.AttackTypes, AttackDataExfiltration)
		result.Reasons = append(result.Reasons, fmt.Sprintf("Potential credit card numbers: %d", len(ccNumbers)))
		riskScore += 0.9
		result.Severity = SeverityHigh
	}

	// Check for API key patterns
	apiKeyRegex := regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?[\w-]{20,}`)
	if apiKeyRegex.MatchString(response) {
		result.AttackDetected = true
		result.AttackTypes = append(result.AttackTypes, AttackDataExfiltration)
		result.Reasons = append(result.Reasons, "Potential API key exposure")
		riskScore += 0.8
		result.Severity = SeverityHigh
	}

	if result.AttackDetected {
		result.Confidence = minFloat(riskScore, 1.0)
		result.RiskScore = riskScore * 100
		result.SuggestedActions = []string{
			"redact_response",
			"alert_admin",
			"audit_log",
		}
	}

	return result
}

// AnalyzeAIRequestPattern analyzes request patterns for anomaly detection
func (s *genaiAttackDetectionService) AnalyzeAIRequestPattern(ctx context.Context, userID, agentID string, timeWindow time.Duration) (*GenAIRequestPattern, error) {
	// Query recent requests for this user/agent
	rows, err := s.db.Pool.Query(ctx, `
		SELECT COUNT(*) as request_count,
			AVG(LENGTH(prompt)) as avg_prompt_len,
			MIN(created_at) as first_seen,
			MAX(created_at) as last_seen
		FROM genai_audit_logs
		WHERE user_id = $1 AND agent_id = $2
			AND created_at > NOW() - $3::interval
	`, userID, agentID, fmt.Sprintf("%d seconds", int(timeWindow.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("failed to query request patterns: %w", err)
	}
	defer rows.Close()

	var pattern GenAIRequestPattern
	pattern.UserID = userID
	pattern.AgentID = agentID

	if rows.Next() {
		var avgLen float64
		var firstSeen, lastSeen time.Time
		rows.Scan(&pattern.RequestFrequency, &avgLen, &firstSeen, &lastSeen)
		pattern.AveragePromptLength = avgLen
		pattern.LastAnalyzed = time.Now()
	}

	// Analyze common patterns from recent prompts
	patternRows, err := s.db.Pool.Query(ctx, `
		SELECT DISTINCT prompt
		FROM genai_audit_logs
		WHERE user_id = $1 AND agent_id = $2
			AND created_at > NOW() - $3::interval
		ORDER BY created_at DESC
		LIMIT 20
	`, userID, agentID, fmt.Sprintf("%d seconds", int(timeWindow.Seconds())))
	if err == nil {
		defer patternRows.Close()
		patterns := []string{}
		for patternRows.Next() {
			var prompt string
			patternRows.Scan(&prompt)
			patterns = append(patterns, extractKeywords(prompt)...)
		}
		pattern.CommonPatterns = uniqueStrings(patterns)
	}

	// Calculate risk score based on frequency and patterns
	pattern.RiskScore = calculatePatternRiskScore(&pattern)

	return &pattern, nil
}

// GetAttackMetrics retrieves attack detection metrics
func (s *genaiAttackDetectionService) GetAttackMetrics(ctx context.Context, timeRange string) (*GenAIAttackMetrics, error) {
	metrics := &GenAIAttackMetrics{
		AttacksByType:     make(map[GenAIAttackType]int64),
		AttacksBySeverity: make(map[GenAIAttackSeverity]int64),
		TimeRange:         timeRange,
		GeneratedAt:       time.Now(),
	}

	// Get total requests
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM genai_audit_logs
		WHERE created_at > NOW() - $1::interval
	`, timeRange).Scan(&metrics.TotalRequests)

	// Get attacks detected
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM genai_attack_incidents
		WHERE created_at > NOW() - $1::interval
	`, timeRange).Scan(&metrics.AttacksDetected)

	// Get attacks by type
	typeRows, _ := s.db.Pool.Query(ctx, `
		SELECT attack_type, COUNT(*) FROM genai_attack_incidents
		WHERE created_at > NOW() - $1::interval
		GROUP BY attack_type
	`, timeRange)
	if typeRows != nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var attackType string
			var count int64
			typeRows.Scan(&attackType, &count)
			metrics.AttacksByType[GenAIAttackType(attackType)] = count
		}
	}

	// Get attacks by severity
	severityRows, _ := s.db.Pool.Query(ctx, `
		SELECT severity, COUNT(*) FROM genai_attack_incidents
		WHERE created_at > NOW() - $1::interval
		GROUP BY severity
	`, timeRange)
	if severityRows != nil {
		defer severityRows.Close()
		for severityRows.Next() {
			var severity string
			var count int64
			severityRows.Scan(&severity, &count)
			metrics.AttacksBySeverity[GenAIAttackSeverity(severity)] = count
		}
	}

	// Get top attack sources
	sourceRows, _ := s.db.Pool.Query(ctx, `
		SELECT user_id, COALESCE(ip_address, ''), COUNT(*) as count, MAX(created_at) as last_seen
		FROM genai_attack_incidents
		WHERE created_at > NOW() - $1::interval
		GROUP BY user_id, ip_address
		ORDER BY count DESC
		LIMIT 10
	`, timeRange)
	if sourceRows != nil {
		defer sourceRows.Close()
		for sourceRows.Next() {
			var source AttackSource
			sourceRows.Scan(&source.UserID, &source.IPAddress, &source.Count, &source.LastSeen)
			metrics.TopAttackSources = append(metrics.TopAttackSources, source)
		}
	}

	return metrics, nil
}

// CreateSecurityRule creates a new security rule
func (s *genaiAttackDetectionService) CreateSecurityRule(ctx context.Context, rule *GenAISecurityRule) error {
	rule.ID = uuid.New().String()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	patternsJSON, _ := json.Marshal(rule.Patterns)
	keywordsJSON, _ := json.Marshal(rule.Keywords)

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO genai_security_rules (id, name, description, attack_type, enabled, patterns, keywords, action, severity, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, rule.ID, rule.Name, rule.Description, rule.AttackType, rule.Enabled,
		patternsJSON, keywordsJSON, rule.Action, rule.Severity,
		rule.CreatedAt, rule.UpdatedAt)

	return err
}

// Helper functions

func compareSeverity(a, b GenAIAttackSeverity) int {
	order := map[GenAIAttackSeverity]int{
		SeverityLow:      0,
		SeverityMedium:   1,
		SeverityHigh:     2,
		SeverityCritical: 3,
	}
	return order[a] - order[b]
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func extractKeywords(prompt string) []string {
	// Simple keyword extraction
	words := strings.Fields(strings.ToLower(prompt))
	keywords := []string{}
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "is": true, "are": true,
		"was": true, "were": true, "be": true, "been": true,
	}
	for _, word := range words {
		if len(word) > 3 && !stopWords[word] {
			keywords = append(keywords, word)
		}
	}
	return keywords[:minInt(len(keywords), 5)]
}

func uniqueStrings(strs []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func calculatePatternRiskScore(pattern *GenAIRequestPattern) float64 {
	score := 0.0

	// High frequency = higher risk
	if pattern.RequestFrequency > 100 {
		score += 0.3
	} else if pattern.RequestFrequency > 50 {
		score += 0.2
	} else if pattern.RequestFrequency > 20 {
		score += 0.1
	}

	// Very short or very long prompts = higher risk
	if pattern.AveragePromptLength > 2000 {
		score += 0.2
	} else if pattern.AveragePromptLength < 50 {
		score += 0.1
	}

	// Suspicious keywords
	suspiciousKeywords := []string{"ignore", "forget", "override", "bypass", "dump", "export"}
	for _, pattern := range pattern.CommonPatterns {
		for _, keyword := range suspiciousKeywords {
			if strings.Contains(strings.ToLower(pattern), keyword) {
				score += 0.15
			}
		}
	}

	return minFloat(score, 1.0) * 100
}

// Handlers

func (s *Service) handleGenAIAttackDetect(c *gin.Context) {
	ctx := c.Request.Context()

	var req GenAIAttackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now()
	}

	detector := &genaiAttackDetectionService{db: s.db, logger: s.logger}
	result := detector.DetectPromptInjection(ctx, &req)

	// Log the analysis
	_, _ = s.db.Pool.Exec(ctx, `
		INSERT INTO genai_audit_logs (request_id, user_id, agent_id, prompt, attack_detected, attack_types, severity, risk_score, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
	`, req.RequestID, req.UserID, req.AgentID, req.Prompt,
		result.AttackDetected, result.AttackTypes, result.Severity, result.RiskScore)

	c.JSON(http.StatusOK, result)
}

func (s *Service) handleGenAIAttackMetrics(c *gin.Context) {
	ctx := c.Request.Context()
	timeRange := c.DefaultQuery("range", "24 hours")

	detector := &genaiAttackDetectionService{db: s.db, logger: s.logger}
	metrics, err := detector.GetAttackMetrics(ctx, timeRange)
	if err != nil {
		s.logger.Error("failed to get attack metrics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get metrics"})
		return
	}

	c.JSON(http.StatusOK, metrics)
}

func (s *Service) handleGenAISecurityRules(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, attack_type, enabled, patterns, keywords, action, severity, created_at, updated_at
		FROM genai_security_rules
		ORDER BY created_at DESC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list rules"})
		return
	}
	defer rows.Close()

	rules := []GenAISecurityRule{}
	for rows.Next() {
		var rule GenAISecurityRule
		var patternsJSON, keywordsJSON []byte
		rows.Scan(&rule.ID, &rule.Name, &rule.Description, &rule.AttackType,
			&rule.Enabled, &patternsJSON, &keywordsJSON, &rule.Action,
			&rule.Severity, &rule.CreatedAt, &rule.UpdatedAt)
		json.Unmarshal(patternsJSON, &rule.Patterns)
		json.Unmarshal(keywordsJSON, &rule.Keywords)
		rules = append(rules, rule)
	}

	c.JSON(http.StatusOK, gin.H{"data": rules})
}
