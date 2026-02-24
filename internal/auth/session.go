// Package auth provides Redis-backed session management for OpenIDX
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var (
	// ErrSessionNotFound is returned when a session does not exist
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired is returned when a session has expired
	ErrSessionExpired = errors.New("session has expired")

	// ErrMaxSessionsReached is returned when user has reached max concurrent sessions
	ErrMaxSessionsReached = errors.New("maximum concurrent sessions reached")

	// ErrInvalidSessionData is returned when session data is invalid
	ErrInvalidSessionData = errors.New("invalid session data")
)

// Session represents a user session
type Session struct {
	ID        string                 `json:"id"`        // Unique session ID
	UserID    string                 `json:"user_id"`   // User ID
	TenantID  string                 `json:"tenant_id"` // Tenant ID (optional)
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	LastSeen  time.Time              `json:"last_seen"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"` // Optional metadata
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
}

// SessionConfig holds configuration for session management
type SessionConfig struct {
	DefaultTTL       time.Duration // Default session timeout (default: 24h)
	MaxSessions      int           // Max concurrent sessions per user (default: 5)
	CleanupInterval  time.Duration // How often to clean expired sessions (default: 1h)
	KeyPrefix        string        // Redis key prefix (default: "session:")
	UserSessionsPrefix string      // Prefix for user session tracking (default: "user_sessions:")
}

// DefaultSessionConfig returns sensible defaults for session configuration
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		DefaultTTL:        24 * time.Hour,
		MaxSessions:       5,
		CleanupInterval:   1 * time.Hour,
		KeyPrefix:         "session:",
		UserSessionsPrefix: "user_sessions:",
	}
}

// SessionService handles session lifecycle in Redis
type SessionService struct {
	redis    *redis.Client
	config   SessionConfig
	logger   *zap.Logger
	stopChan chan struct{}
}

// NewSessionService creates a new SessionService
func NewSessionService(redisClient *redis.Client, logger *zap.Logger) *SessionService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &SessionService{
		redis:    redisClient,
		config:   DefaultSessionConfig(),
		logger:   logger,
		stopChan: make(chan struct{}),
	}
}

// WithConfig sets a custom session configuration
func (ss *SessionService) WithConfig(config SessionConfig) *SessionService {
	// Only set non-zero values to preserve defaults
	if config.DefaultTTL > 0 {
		ss.config.DefaultTTL = config.DefaultTTL
	}
	if config.MaxSessions > 0 {
		ss.config.MaxSessions = config.MaxSessions
	}
	if config.CleanupInterval > 0 {
		ss.config.CleanupInterval = config.CleanupInterval
	}
	if config.KeyPrefix != "" {
		ss.config.KeyPrefix = config.KeyPrefix
	}
	if config.UserSessionsPrefix != "" {
		ss.config.UserSessionsPrefix = config.UserSessionsPrefix
	}
	return ss
}

// Create creates a new session for a user, enforcing max concurrent session limit
func (ss *SessionService) Create(ctx context.Context, userID, tenantID, ipAddress, userAgent string, metadata map[string]interface{}) (*Session, error) {
	if ss.redis == nil {
		return nil, errors.New("redis client not configured")
	}

	// Check current session count
	currentCount, err := ss.getCount(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get session count: %w", err)
	}

	// Enforce max sessions limit
	if currentCount >= ss.config.MaxSessions {
		// Optionally: delete oldest session
		if err := ss.deleteOldestSession(ctx, userID); err != nil {
			ss.logger.Warn("failed to delete oldest session", zap.Error(err))
		} else {
			currentCount--
		}
	}

	if currentCount >= ss.config.MaxSessions {
		return nil, fmt.Errorf("%w: maximum %d sessions allowed", ErrMaxSessionsReached, ss.config.MaxSessions)
	}

	// Create new session
	sessionID := uuid.New().String()
	now := time.Now()
	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		TenantID:  tenantID,
		CreatedAt: now,
		ExpiresAt: now.Add(ss.config.DefaultTTL),
		LastSeen:  now,
		Metadata:  metadata,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	// Serialize and store in Redis
	data, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("marshal session: %w", err)
	}

	// Store session data
	sessionKey := ss.sessionKey(sessionID)
	if err := ss.redis.Set(ctx, sessionKey, data, ss.config.DefaultTTL).Err(); err != nil {
		return nil, fmt.Errorf("set session: %w", err)
	}

	// Add to user's session set
	userSessionsKey := ss.userSessionsKey(userID)
	if err := ss.redis.SAdd(ctx, userSessionsKey, sessionID).Err(); err != nil {
		// Rollback session creation
		ss.redis.Del(ctx, sessionKey)
		return nil, fmt.Errorf("add to user sessions: %w", err)
	}

	// Set expiry on user sessions set
	ss.redis.Expire(ctx, userSessionsKey, ss.config.DefaultTTL*2)

	ss.logger.Debug("created session",
		zap.String("session_id", sessionID),
		zap.String("user_id", userID),
		zap.Time("expires_at", session.ExpiresAt),
	)

	return session, nil
}

// Get retrieves a session by ID
func (ss *SessionService) Get(ctx context.Context, sessionID string) (*Session, error) {
	if ss.redis == nil {
		return nil, errors.New("redis client not configured")
	}

	sessionKey := ss.sessionKey(sessionID)
	data, err := ss.redis.Get(ctx, sessionKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, ErrInvalidSessionData
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session
		ss.Delete(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	// Update last seen asynchronously (fire and forget)
	// Note: This could race with Delete operations, but that's acceptable for a last-seen update
	go func() {
		refreshCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		session.LastSeen = time.Now()
		if newData, err := json.Marshal(session); err == nil {
			// Only update if session still exists
			if ss.redis.Exists(refreshCtx, sessionKey).Val() > 0 {
				ss.redis.Expire(refreshCtx, sessionKey, ss.config.DefaultTTL)
				ss.redis.Set(refreshCtx, sessionKey, newData, ss.config.DefaultTTL)
			}
		}
	}()

	return &session, nil
}

// Delete removes a session by ID
func (ss *SessionService) Delete(ctx context.Context, sessionID string) error {
	if ss.redis == nil {
		return errors.New("redis client not configured")
	}

	// Get session to find userID for cleanup
	session, err := ss.Get(ctx, sessionID)
	if err != nil && err != ErrSessionExpired {
		return err
	}

	// Delete session data
	sessionKey := ss.sessionKey(sessionID)
	if err := ss.redis.Del(ctx, sessionKey).Err(); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	// Remove from user's session set
	if session != nil {
		userSessionsKey := ss.userSessionsKey(session.UserID)
		ss.redis.SRem(ctx, userSessionsKey, sessionID)
	}

	ss.logger.Debug("deleted session", zap.String("session_id", sessionID))
	return nil
}

// DeleteByUser removes all sessions for a user. Returns ErrSessionNotFound if the user has no sessions.
func (ss *SessionService) DeleteByUser(ctx context.Context, userID string) error {
	if ss.redis == nil {
		return errors.New("redis client not configured")
	}

	// Get all session IDs for the user
	sessionIDs, err := ss.ListByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("list user sessions: %w", err)
	}

	// Return error if user has no sessions
	if len(sessionIDs) == 0 {
		return ErrSessionNotFound
	}

	// Delete each session
	for _, sessionID := range sessionIDs {
		if err := ss.Delete(ctx, sessionID); err != nil {
			ss.logger.Warn("failed to delete session",
				zap.String("session_id", sessionID),
				zap.Error(err),
			)
		}
	}

	// Clear the user's session set
	userSessionsKey := ss.userSessionsKey(userID)
	ss.redis.Del(ctx, userSessionsKey)

	ss.logger.Debug("deleted all sessions for user", zap.String("user_id", userID))
	return nil
}

// ListByUser returns all session IDs for a user
func (ss *SessionService) ListByUser(ctx context.Context, userID string) ([]string, error) {
	if ss.redis == nil {
		return nil, errors.New("redis client not configured")
	}

	userSessionsKey := ss.userSessionsKey(userID)
	members, err := ss.redis.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return nil, fmt.Errorf("get user sessions: %w", err)
	}

	// Filter out expired/non-existent sessions
	var validSessions []string
	for _, sessionID := range members {
		sessionKey := ss.sessionKey(sessionID)
		exists, err := ss.redis.Exists(ctx, sessionKey).Result()
		if err == nil && exists > 0 {
			validSessions = append(validSessions, sessionID)
		} else {
			// Clean up stale session ID from set
			ss.redis.SRem(ctx, userSessionsKey, sessionID)
		}
	}

	return validSessions, nil
}

// GetByUser returns all active session objects for a user
func (ss *SessionService) GetByUser(ctx context.Context, userID string) ([]*Session, error) {
	sessionIDs, err := ss.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	var sessions []*Session
	for _, sessionID := range sessionIDs {
		session, err := ss.Get(ctx, sessionID)
		if err == nil {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// Refresh extends the expiration time of a session
func (ss *SessionService) Refresh(ctx context.Context, sessionID string) error {
	if ss.redis == nil {
		return errors.New("redis client not configured")
	}

	session, err := ss.Get(ctx, sessionID)
	if err != nil {
		return err
	}

	session.ExpiresAt = time.Now().Add(ss.config.DefaultTTL)
	session.LastSeen = time.Now()

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	sessionKey := ss.sessionKey(sessionID)
	if err := ss.redis.Set(ctx, sessionKey, data, ss.config.DefaultTTL).Err(); err != nil {
		return fmt.Errorf("refresh session: %w", err)
	}

	ss.logger.Debug("refreshed session",
		zap.String("session_id", sessionID),
		zap.Time("new_expires_at", session.ExpiresAt),
	)

	return nil
}

// UpdateMetadata updates the metadata for a session
func (ss *SessionService) UpdateMetadata(ctx context.Context, sessionID string, metadata map[string]interface{}) error {
	if ss.redis == nil {
		return errors.New("redis client not configured")
	}

	session, err := ss.Get(ctx, sessionID)
	if err != nil {
		return err
	}

	session.Metadata = metadata
	session.LastSeen = time.Now()

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	sessionKey := ss.sessionKey(sessionID)
	if err := ss.redis.Set(ctx, sessionKey, data, ss.config.DefaultTTL).Err(); err != nil {
		return fmt.Errorf("update session metadata: %w", err)
	}

	return nil
}

// getCount returns the current number of active sessions for a user
func (ss *SessionService) getCount(ctx context.Context, userID string) (int, error) {
	sessionIDs, err := ss.ListByUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	return len(sessionIDs), nil
}

// deleteOldestSession deletes the oldest session for a user
func (ss *SessionService) deleteOldestSession(ctx context.Context, userID string) error {
	sessions, err := ss.GetByUser(ctx, userID)
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		return nil
	}

	// Find oldest session
	var oldest *Session
	for _, s := range sessions {
		if oldest == nil || s.CreatedAt.Before(oldest.CreatedAt) {
			oldest = s
		}
	}

	if oldest != nil {
		return ss.Delete(ctx, oldest.ID)
	}

	return nil
}

// sessionKey returns the Redis key for a session
func (ss *SessionService) sessionKey(sessionID string) string {
	return ss.config.KeyPrefix + sessionID
}

// userSessionsKey returns the Redis key for a user's session set
func (ss *SessionService) userSessionsKey(userID string) string {
	return ss.config.UserSessionsPrefix + userID
}

// StartCleanup starts a background goroutine to clean expired sessions
func (ss *SessionService) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(ss.config.CleanupInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ss.cleanup(ctx)
			case <-ss.stopChan:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// StopCleanup stops the background cleanup goroutine
func (ss *SessionService) StopCleanup() {
	close(ss.stopChan)
}

// cleanup removes expired sessions from Redis
func (ss *SessionService) cleanup(ctx context.Context) {
	if ss.redis == nil {
		return
	}

	// Scan for session keys
	iter := ss.redis.Scan(ctx, 0, ss.config.KeyPrefix+"*", 100).Iterator()
	var deletedCount int

	for iter.Next(ctx) {
		sessionKey := iter.Val()
		data, err := ss.redis.Get(ctx, sessionKey).Bytes()
		if err != nil {
			if err == redis.Nil {
				// Key doesn't exist, already cleaned
				continue
			}
			continue
		}

		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			// Invalid data, delete
			ss.redis.Del(ctx, sessionKey)
			deletedCount++
			continue
		}

		// Check if expired
		if time.Now().After(session.ExpiresAt) {
			ss.redis.Del(ctx, sessionKey)
			// Also remove from user's session set
			userSessionsKey := ss.userSessionsKey(session.UserID)
			ss.redis.SRem(ctx, userSessionsKey, session.ID)
			deletedCount++
		}
	}

	if err := iter.Err(); err != nil {
		ss.logger.Error("cleanup iteration error", zap.Error(err))
	}

	if deletedCount > 0 {
		ss.logger.Debug("cleaned expired sessions", zap.Int("count", deletedCount))
	}
}
