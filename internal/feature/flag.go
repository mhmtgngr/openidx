// Package feature provides a comprehensive feature flag system for OpenIDX
// supporting multiple storage backends, user targeting, percentage rollouts,
// A/B testing, and audit logging.
package feature

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

//go:generate go run github.com/matryer/moxqgen -out flag_mock.go

// StorageType defines where feature flags are stored
type StorageType int

const (
	// StorageMemory stores flags in memory only (development)
	StorageMemory StorageType = iota
	// StorageRedis stores flags in Redis (production, distributed)
	StorageRedis
	// StorageDatabase stores flags in database (persistent)
	StorageDatabase
)

// Flag represents a feature flag configuration
type Flag struct {
	Name          string   `json:"name"`
	Enabled       bool     `json:"enabled"`
	Percentage    int      `json:"percentage"`    // 0-100 for percentage rollouts
	UserWhitelist []string `json:"userWhitelist"` // Users always included
	UserBlacklist []string `json:"userBlacklist"` // Users always excluded
	Description   string   `json:"description"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	UpdatedBy     string    `json:"updatedBy"` // User who last updated the flag
	Variant       string    `json:"variant"`   // For A/B testing
	// Variants defines A/B test variants with allocation percentages
	Variants []Variant `json:"variants,omitempty"`
	// Metadata for custom attributes
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Variant represents an A/B test variant
type Variant struct {
	Name        string  `json:"name"`
	Percentage  float64 `json:"percentage"` // 0-100
	Description string  `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

// FlagConfig is the configuration for creating/updating a flag
type FlagConfig struct {
	Name          string
	Enabled       bool
	Percentage    int
	UserWhitelist []string
	UserBlacklist []string
	Description   string
	Variant       string
	Variants      []Variant
	Metadata      map[string]interface{}
}

// FlagChange represents a change to a feature flag for auditing
type FlagChange struct {
	FlagName    string                 `json:"flag_name"`
	Action      string                 `json:"action"` // created, updated, deleted, enabled, disabled
	Actor       string                 `json:"actor"`
	ActorEmail  string                 `json:"actor_email,omitempty"`
	OldValue    *Flag                  `json:"old_value,omitempty"`
	NewValue    *Flag                  `json:"new_value,omitempty"`
	ChangedAt   time.Time              `json:"changed_at"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Changes     map[string]interface{} `json:"changes,omitempty"`
}

// Store defines the interface for feature flag storage
type Store interface {
	Get(ctx context.Context, name string) (*Flag, error)
	Set(ctx context.Context, flag *Flag) error
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]*Flag, error)
}

// MemoryStore implements in-memory flag storage
type MemoryStore struct {
	mu    sync.RWMutex
	flags map[string]*Flag
}

// NewMemoryStore creates a new in-memory flag store
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		flags: make(map[string]*Flag),
	}
}

// Get retrieves a flag from memory
func (m *MemoryStore) Get(ctx context.Context, name string) (*Flag, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	flag, exists := m.flags[name]
	if !exists {
		return nil, ErrFlagNotFound
	}
	return flag, nil
}

// Set stores a flag in memory
func (m *MemoryStore) Set(ctx context.Context, flag *Flag) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	flag.UpdatedAt = time.Now()
	if flag.CreatedAt.IsZero() {
		flag.CreatedAt = time.Now()
	}
	m.flags[flag.Name] = flag
	return nil
}

// Delete removes a flag from memory
func (m *MemoryStore) Delete(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.flags[name]; !exists {
		return ErrFlagNotFound
	}
	delete(m.flags, name)
	return nil
}

// List returns all flags from memory
func (m *MemoryStore) List(ctx context.Context) ([]*Flag, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	flags := make([]*Flag, 0, len(m.flags))
	for _, flag := range m.flags {
		flags = append(flags, flag)
	}
	return flags, nil
}

// RedisStore implements Redis-backed flag storage
type RedisStore struct {
	client *redis.Client
	keyPrefix string
}

// NewRedisStore creates a new Redis-backed flag store
func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{
		client: client,
		keyPrefix: "feature_flag:",
	}
}

// Get retrieves a flag from Redis
func (r *RedisStore) Get(ctx context.Context, name string) (*Flag, error) {
	if r.client == nil {
		return nil, ErrStoreUnavailable
	}

	key := r.keyPrefix + name
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrFlagNotFound
		}
		return nil, fmt.Errorf("failed to get flag from Redis: %w", err)
	}

	var flag Flag
	if err := json.Unmarshal(data, &flag); err != nil {
		return nil, fmt.Errorf("failed to unmarshal flag: %w", err)
	}

	return &flag, nil
}

// Set stores a flag in Redis
func (r *RedisStore) Set(ctx context.Context, flag *Flag) error {
	if r.client == nil {
		return ErrStoreUnavailable
	}

	flag.UpdatedAt = time.Now()
	if flag.CreatedAt.IsZero() {
		flag.CreatedAt = time.Now()
	}

	data, err := json.Marshal(flag)
	if err != nil {
		return fmt.Errorf("failed to marshal flag: %w", err)
	}

	key := r.keyPrefix + flag.Name
	if err := r.client.Set(ctx, key, data, 0).Err(); err != nil {
		return fmt.Errorf("failed to set flag in Redis: %w", err)
	}

	return nil
}

// Delete removes a flag from Redis
func (r *RedisStore) Delete(ctx context.Context, name string) error {
	if r.client == nil {
		return ErrStoreUnavailable
	}

	key := r.keyPrefix + name
	result, err := r.client.Del(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to delete flag from Redis: %w", err)
	}
	if result == 0 {
		return ErrFlagNotFound
	}

	return nil
}

// List returns all flags from Redis
func (r *RedisStore) List(ctx context.Context) ([]*Flag, error) {
	if r.client == nil {
		return nil, ErrStoreUnavailable
	}

	iter := r.client.Scan(ctx, 0, r.keyPrefix+"*", 100).Iterator()
	var flags []*Flag

	for iter.Next(ctx) {
		key := iter.Val()
		data, err := r.client.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var flag Flag
		if err := json.Unmarshal(data, &flag); err != nil {
			continue
		}
		flags = append(flags, &flag)
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan flags: %w", err)
	}

	return flags, nil
}

// Service provides the main feature flag functionality
type Service struct {
	store      Store
	logger     *zap.Logger
	audit      AuditLogger
	storageType StorageType

	// Local cache for faster reads
	localCache   map[string]*Flag
	localCacheMu sync.RWMutex
	cacheTTL     time.Duration
	lastCacheSync time.Time
}

// AuditLogger defines the interface for logging flag changes
type AuditLogger interface {
	LogFeatureFlagChange(change *FlagChange)
}

// NewService creates a new feature flag service
func NewService(storageType StorageType, redisClient *redis.Client, logger *zap.Logger, audit AuditLogger) *Service {
	s := &Service{
		storageType: storageType,
		logger:      logger.With(zap.String("component", "feature_flag")),
		audit:       audit,
		localCache:  make(map[string]*Flag),
		cacheTTL:    1 * time.Minute,
	}

	switch storageType {
	case StorageRedis:
		s.store = NewRedisStore(redisClient)
	case StorageMemory:
		s.store = NewMemoryStore()
	case StorageDatabase:
		// TODO: Implement database store
		s.store = NewMemoryStore()
	}

	return s
}

// IsEnabled checks if a feature flag is enabled for a specific user
// It checks:
// 1. If flag exists and is enabled
// 2. If user is in whitelist (always enabled)
// 3. If user is in blacklist (always disabled)
// 4. If user falls within the percentage rollout
func (s *Service) IsEnabled(ctx context.Context, flag string, userID string) bool {
	flagConfig, err := s.GetFlagConfig(ctx, flag)
	if err != nil {
		s.logger.Debug("Flag not found, defaulting to disabled",
			zap.String("flag", flag),
			zap.Error(err),
		)
		return false
	}

	return s.isEnabledForUser(flagConfig, userID)
}

// IsEnabledForPercentage checks if a flag is enabled based on percentage rollout
// Uses consistent hashing to ensure the same user gets the same experience
func (s *Service) IsEnabledForPercentage(ctx context.Context, flag string, userID string) bool {
	flagConfig, err := s.GetFlagConfig(ctx, flag)
	if err != nil {
		return false
	}

	if !flagConfig.Enabled {
		return false
	}

	return s.getUserPercentage(userID, flag) < flagConfig.Percentage
}

// GetFlagConfig retrieves the configuration for a flag
func (s *Service) GetFlagConfig(ctx context.Context, flag string) (*Flag, error) {
	// Try local cache first
	s.localCacheMu.RLock()
	cached, exists := s.localCache[flag]
	s.localCacheMu.RUnlock()

	if exists && time.Since(s.lastCacheSync) < s.cacheTTL {
		return cached, nil
	}

	// Fetch from store
	flagConfig, err := s.store.Get(ctx, flag)
	if err != nil {
		return nil, err
	}

	// Update cache
	s.localCacheMu.Lock()
	s.localCache[flag] = flagConfig
	s.lastCacheSync = time.Now()
	s.localCacheMu.Unlock()

	return flagConfig, nil
}

// SetFlag creates or updates a feature flag
func (s *Service) SetFlag(ctx context.Context, flag string, config *FlagConfig, actor string) error {
	// Get old value for audit
	oldFlag, _ := s.store.Get(ctx, flag)

	// Create new flag
	newFlag := &Flag{
		Name:          flag,
		Enabled:       config.Enabled,
		Percentage:    config.Percentage,
		UserWhitelist: config.UserWhitelist,
		UserBlacklist: config.UserBlacklist,
		Description:   config.Description,
		Variant:       config.Variant,
		Variants:      config.Variants,
		Metadata:      config.Metadata,
		UpdatedBy:     actor,
	}

	if oldFlag != nil {
		newFlag.CreatedAt = oldFlag.CreatedAt
	}

	// Validate flag
	if err := s.validateFlag(newFlag); err != nil {
		return fmt.Errorf("invalid flag configuration: %w", err)
	}

	// Store the flag
	if err := s.store.Set(ctx, newFlag); err != nil {
		return err
	}

	// Update local cache
	s.localCacheMu.Lock()
	s.localCache[flag] = newFlag
	s.lastCacheSync = time.Now()
	s.localCacheMu.Unlock()

	// Audit the change
	if s.audit != nil {
		changes := s.detectChanges(oldFlag, newFlag)
		s.audit.LogFeatureFlagChange(&FlagChange{
			FlagName:   flag,
			Action:     s.getChangeAction(oldFlag),
			Actor:      actor,
			OldValue:   oldFlag,
			NewValue:   newFlag,
			ChangedAt:  time.Now(),
			Changes:    changes,
		})
	}

	s.logger.Info("Feature flag updated",
		zap.String("flag", flag),
		zap.Bool("enabled", newFlag.Enabled),
		zap.Int("percentage", newFlag.Percentage),
		zap.String("actor", actor),
	)

	return nil
}

// DeleteFlag removes a feature flag
func (s *Service) DeleteFlag(ctx context.Context, flag string, actor string) error {
	oldFlag, err := s.store.Get(ctx, flag)
	if err != nil {
		return err
	}

	if err := s.store.Delete(ctx, flag); err != nil {
		return err
	}

	// Remove from cache
	s.localCacheMu.Lock()
	delete(s.localCache, flag)
	s.localCacheMu.Unlock()

	// Audit the deletion
	if s.audit != nil {
		s.audit.LogFeatureFlagChange(&FlagChange{
			FlagName:  flag,
			Action:    "deleted",
			Actor:     actor,
			OldValue:  oldFlag,
			ChangedAt: time.Now(),
		})
	}

	s.logger.Info("Feature flag deleted",
		zap.String("flag", flag),
		zap.String("actor", actor),
	)

	return nil
}

// ListFlags returns all feature flags
func (s *Service) ListFlags(ctx context.Context) ([]*Flag, error) {
	return s.store.List(ctx)
}

// GetVariant returns the A/B test variant for a user
func (s *Service) GetVariant(ctx context.Context, flag string, userID string) (string, error) {
	flagConfig, err := s.GetFlagConfig(ctx, flag)
	if err != nil {
		return "", err
	}

	if !flagConfig.Enabled {
		return "", nil
	}

	// Check if user has an explicit variant set via metadata
	if flagConfig.Metadata != nil {
		if userVariant, ok := flagConfig.Metadata["user_variant"].(map[string]interface{}); ok {
			if variant, ok := userVariant[userID].(string); ok {
				return variant, nil
			}
		}
	}

	// Calculate variant based on user ID hash
	if len(flagConfig.Variants) > 0 {
		hash := s.getUserPercentage(userID, flag)

		var cumulative float64
		for _, variant := range flagConfig.Variants {
			cumulative += variant.Percentage
			if hash < int(cumulative) {
				return variant.Name, nil
			}
		}
	}

	return flagConfig.Variant, nil
}

// SetUserVariant explicitly sets a variant for a user (for testing)
func (s *Service) SetUserVariant(ctx context.Context, flag, userID, variant string, actor string) error {
	flagConfig, err := s.store.Get(ctx, flag)
	if err != nil {
		return err
	}

	if flagConfig.Metadata == nil {
		flagConfig.Metadata = make(map[string]interface{})
	}

	userVariants, ok := flagConfig.Metadata["user_variant"].(map[string]interface{})
	if !ok {
		userVariants = make(map[string]interface{})
	}

	userVariants[userID] = variant
	flagConfig.Metadata["user_variant"] = userVariants
	flagConfig.UpdatedBy = actor

	if err := s.store.Set(ctx, flagConfig); err != nil {
		return err
	}

	// Update cache
	s.localCacheMu.Lock()
	s.localCache[flag] = flagConfig
	s.lastCacheSync = time.Now()
	s.localCacheMu.Unlock()

	return nil
}

// GetVariantConfig returns the configuration for a specific variant.
// The returned map always includes the variant's "description" and "percentage"
// fields alongside any custom Config entries.
func (s *Service) GetVariantConfig(ctx context.Context, flag, variantName string) (map[string]interface{}, error) {
	flagConfig, err := s.GetFlagConfig(ctx, flag)
	if err != nil {
		return nil, err
	}

	for _, variant := range flagConfig.Variants {
		if variant.Name == variantName {
			result := make(map[string]interface{})
			// Copy custom config entries first
			for k, v := range variant.Config {
				result[k] = v
			}
			// Always include standard variant fields
			if variant.Description != "" {
				result["description"] = variant.Description
			}
			result["percentage"] = variant.Percentage
			return result, nil
		}
	}

	return nil, ErrVariantNotFound
}

// isEnabledForUser determines if a flag is enabled for a specific user
func (s *Service) isEnabledForUser(flag *Flag, userID string) bool {
	if !flag.Enabled {
		return false
	}

	// Check blacklist first (blocklist has priority)
	for _, blockedUser := range flag.UserBlacklist {
		if blockedUser == userID {
			return false
		}
	}

	// Check whitelist
	for _, allowedUser := range flag.UserWhitelist {
		if allowedUser == userID {
			return true
		}
	}

	// Check percentage rollout
	if flag.Percentage > 0 {
		userPercentage := s.getUserPercentage(userID, flag.Name)
		return userPercentage < flag.Percentage
	}

	return false
}

// getUserPercentage calculates a consistent 0-99 value for a user
// using SHA256 hashing to ensure the same user always gets the same value
func (s *Service) getUserPercentage(userID, flag string) int {
	hash := sha256.Sum256([]byte(userID + ":" + flag))
	// Use first 4 bytes to create a 0-99 value
	val := int(hash[0])<<24 | int(hash[1])<<16 | int(hash[2])<<8 | int(hash[3])
	if val < 0 {
		val = -val
	}
	return val % 100
}

// validateFlag validates flag configuration
func (s *Service) validateFlag(flag *Flag) error {
	if flag.Name == "" {
		return ErrInvalidFlagName
	}

	if flag.Percentage < 0 || flag.Percentage > 100 {
		return ErrInvalidPercentage
	}

	// Validate variants
	var totalPercentage float64
	for _, variant := range flag.Variants {
		if variant.Name == "" {
			return fmt.Errorf("variant name cannot be empty")
		}
		if variant.Percentage < 0 || variant.Percentage > 100 {
			return fmt.Errorf("variant percentage must be between 0 and 100")
		}
		totalPercentage += variant.Percentage
	}

	if len(flag.Variants) > 0 && totalPercentage > 100 {
		return fmt.Errorf("total variant percentage cannot exceed 100")
	}

	return nil
}

// detectChanges identifies what changed between two flag versions
func (s *Service) detectChanges(old, new *Flag) map[string]interface{} {
	if old == nil {
		return map[string]interface{}{"action": "created"}
	}

	changes := make(map[string]interface{})

	if old.Enabled != new.Enabled {
		changes["enabled"] = map[string]interface{}{"old": old.Enabled, "new": new.Enabled}
	}
	if old.Percentage != new.Percentage {
		changes["percentage"] = map[string]interface{}{"old": old.Percentage, "new": new.Percentage}
	}
	if old.Description != new.Description {
		changes["description"] = map[string]interface{}{"old": old.Description, "new": new.Description}
	}
	if old.Variant != new.Variant {
		changes["variant"] = map[string]interface{}{"old": old.Variant, "new": new.Variant}
	}

	return changes
}

// getChangeAction determines the type of change
func (s *Service) getChangeAction(old *Flag) string {
	if old == nil {
		return "created"
	}
	if !old.Enabled && old.Percentage == 0 {
		return "enabled"
	}
	return "updated"
}

// InitializeDefaultFlags creates the initial set of feature flags
func (s *Service) InitializeDefaultFlags(ctx context.Context) error {
	defaultFlags := map[string]*FlagConfig{
		"new-auth-flow": {
			Enabled:     false,
			Percentage: 0,
			Description: "New authentication flow with improved UX",
		},
		"enhanced-mfa": {
			Enabled:     true,
			Percentage: 100,
			Description: "Enhanced multi-factor authentication with push notifications",
		},
		"beta-dashboard": {
			Enabled:     false,
			Percentage: 50,
			Description: "Beta version of the admin dashboard with new features",
		},
	}

	for name, config := range defaultFlags {
		// Check if flag already exists
		_, err := s.store.Get(ctx, name)
		if err == ErrFlagNotFound {
			// Create the flag
			if err := s.SetFlag(ctx, name, config, "system"); err != nil {
				s.logger.Error("Failed to create default flag",
					zap.String("flag", name),
					zap.Error(err),
				)
				return err
			}
			s.logger.Info("Created default feature flag", zap.String("flag", name))
		}
	}

	return nil
}

// RefreshCache refreshes the local cache from the backing store
func (s *Service) RefreshCache(ctx context.Context) error {
	flags, err := s.store.List(ctx)
	if err != nil {
		return err
	}

	s.localCacheMu.Lock()
	defer s.localCacheMu.Unlock()

	s.localCache = make(map[string]*Flag)
	for _, flag := range flags {
		s.localCache[flag.Name] = flag
	}
	s.lastCacheSync = time.Now()

	return nil
}

// GetMetrics returns metrics about feature flag usage
func (s *Service) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	flags, err := s.ListFlags(ctx)
	if err != nil {
		return nil, err
	}

	enabledCount := 0
	disabledCount := 0
	totalPercentage := 0

	for _, flag := range flags {
		if flag.Enabled {
			enabledCount++
			totalPercentage += flag.Percentage
		} else {
			disabledCount++
		}
	}

	return map[string]interface{}{
		"total_flags":      len(flags),
		"enabled_flags":    enabledCount,
		"disabled_flags":   disabledCount,
		"avg_percentage":   float64(totalPercentage) / float64(len(flags)),
		"storage_type":     s.storageType.String(),
		"last_cache_sync":  s.lastCacheSync,
	}, nil
}

// String returns the string representation of StorageType
func (s StorageType) String() string {
	switch s {
	case StorageMemory:
		return "memory"
	case StorageRedis:
		return "redis"
	case StorageDatabase:
		return "database"
	default:
		return "unknown"
	}
}

// Error definitions
var (
	ErrFlagNotFound     = fmt.Errorf("feature flag not found")
	ErrStoreUnavailable = fmt.Errorf("flag store unavailable")
	ErrInvalidFlagName  = fmt.Errorf("invalid flag name")
	ErrInvalidPercentage = fmt.Errorf("percentage must be between 0 and 100")
	ErrVariantNotFound   = fmt.Errorf("variant not found")
)
