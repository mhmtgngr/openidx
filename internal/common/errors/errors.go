// Package errors provides structured error handling for OpenIDX
package errors

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorCode represents an application error code
type ErrorCode string

const (
	// General errors
	ErrInternal      ErrorCode = "INTERNAL_ERROR"
	ErrNotFound      ErrorCode = "NOT_FOUND"
	ErrBadRequest    ErrorCode = "BAD_REQUEST"
	ErrUnauthorized  ErrorCode = "UNAUTHORIZED"
	ErrForbidden     ErrorCode = "FORBIDDEN"
	ErrConflict      ErrorCode = "CONFLICT"
	ErrValidation    ErrorCode = "VALIDATION_ERROR"
	ErrTimeout       ErrorCode = "TIMEOUT"
	ErrRateLimit     ErrorCode = "RATE_LIMIT_EXCEEDED"

	// Resource errors
	ErrUserNotFound      ErrorCode = "USER_NOT_FOUND"
	ErrUserAlreadyExists ErrorCode = "USER_ALREADY_EXISTS"
	ErrUserDisabled      ErrorCode = "USER_DISABLED"
	ErrGroupNotFound     ErrorCode = "GROUP_NOT_FOUND"
	ErrGroupAlreadyExists ErrorCode = "GROUP_ALREADY_EXISTS"
	ErrSessionNotFound   ErrorCode = "SESSION_NOT_FOUND"
	ErrSessionExpired    ErrorCode = "SESSION_EXPIRED"

	// Authentication & Authorization errors
	ErrInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	ErrInvalidToken       ErrorCode = "INVALID_TOKEN"
	ErrTokenExpired       ErrorCode = "TOKEN_EXPIRED"
	ErrInsufficientPerms  ErrorCode = "INSUFFICIENT_PERMISSIONS"

	// Policy errors
	ErrPolicyNotFound      ErrorCode = "POLICY_NOT_FOUND"
	ErrPolicyViolation     ErrorCode = "POLICY_VIOLATION"
	ErrPolicyAlreadyExists ErrorCode = "POLICY_ALREADY_EXISTS"

	// Review errors
	ErrReviewNotFound    ErrorCode = "REVIEW_NOT_FOUND"
	ErrReviewAlreadyDone ErrorCode = "REVIEW_ALREADY_COMPLETED"
	ErrInvalidDecision   ErrorCode = "INVALID_DECISION"

	// Database errors
	ErrDatabase        ErrorCode = "DATABASE_ERROR"
	ErrDuplicateKey    ErrorCode = "DUPLICATE_KEY"
	ErrConstraintViolation ErrorCode = "CONSTRAINT_VIOLATION"

	// External service errors
	ErrRedisError    ErrorCode = "REDIS_ERROR"
	ErrElasticsearchError ErrorCode = "ELASTICSEARCH_ERROR"
)

// AppError represents a structured application error
type AppError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    string                 `json:"details,omitempty"`
	StatusCode int                    `json:"-"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Err        error                  `json:"-"` // Original error for logging
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the original error
func (e *AppError) Unwrap() error {
	return e.Err
}

// WithMetadata adds metadata to the error
func (e *AppError) WithMetadata(key string, value interface{}) *AppError {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

// WithDetails adds details to the error
func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

// New creates a new AppError
func New(code ErrorCode, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
	}
}

// Wrap wraps an existing error into an AppError
func Wrap(err error, code ErrorCode, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Err:        err,
	}
}

// Predefined errors

// Internal creates an internal server error
func Internal(message string, err error) *AppError {
	return &AppError{
		Code:       ErrInternal,
		Message:    message,
		StatusCode: http.StatusInternalServerError,
		Err:        err,
	}
}

// NotFound creates a not found error
func NotFound(resource string) *AppError {
	return &AppError{
		Code:       ErrNotFound,
		Message:    fmt.Sprintf("%s not found", resource),
		StatusCode: http.StatusNotFound,
	}
}

// BadRequest creates a bad request error
func BadRequest(message string) *AppError {
	return &AppError{
		Code:       ErrBadRequest,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// Unauthorized creates an unauthorized error
func Unauthorized(message string) *AppError {
	return &AppError{
		Code:       ErrUnauthorized,
		Message:    message,
		StatusCode: http.StatusUnauthorized,
	}
}

// Forbidden creates a forbidden error
func Forbidden(message string) *AppError {
	return &AppError{
		Code:       ErrForbidden,
		Message:    message,
		StatusCode: http.StatusForbidden,
	}
}

// Conflict creates a conflict error
func Conflict(message string) *AppError {
	return &AppError{
		Code:       ErrConflict,
		Message:    message,
		StatusCode: http.StatusConflict,
	}
}

// ValidationError creates a validation error
func ValidationError(message string) *AppError {
	return &AppError{
		Code:       ErrValidation,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// Timeout creates a timeout error
func Timeout(message string) *AppError {
	return &AppError{
		Code:       ErrTimeout,
		Message:    message,
		StatusCode: http.StatusGatewayTimeout,
	}
}

// RateLimit creates a rate limit error
func RateLimit(message string) *AppError {
	return &AppError{
		Code:       ErrRateLimit,
		Message:    message,
		StatusCode: http.StatusTooManyRequests,
	}
}

// Resource-specific errors

// UserNotFound creates a user not found error
func UserNotFound(userID string) *AppError {
	return (&AppError{
		Code:       ErrUserNotFound,
		Message:    "User not found",
		StatusCode: http.StatusNotFound,
	}).WithMetadata("user_id", userID)
}

// UserAlreadyExists creates a user already exists error
func UserAlreadyExists(username string) *AppError {
	return (&AppError{
		Code:       ErrUserAlreadyExists,
		Message:    "User already exists",
		StatusCode: http.StatusConflict,
	}).WithMetadata("username", username)
}

// UserDisabled creates a user disabled error
func UserDisabled(userID string) *AppError {
	return (&AppError{
		Code:       ErrUserDisabled,
		Message:    "User is disabled",
		StatusCode: http.StatusForbidden,
	}).WithMetadata("user_id", userID)
}

// GroupNotFound creates a group not found error
func GroupNotFound(groupID string) *AppError {
	return (&AppError{
		Code:       ErrGroupNotFound,
		Message:    "Group not found",
		StatusCode: http.StatusNotFound,
	}).WithMetadata("group_id", groupID)
}

// GroupAlreadyExists creates a group already exists error
func GroupAlreadyExists(name string) *AppError {
	return (&AppError{
		Code:       ErrGroupAlreadyExists,
		Message:    "Group already exists",
		StatusCode: http.StatusConflict,
	}).WithMetadata("group_name", name)
}

// SessionNotFound creates a session not found error
func SessionNotFound(sessionID string) *AppError {
	return (&AppError{
		Code:       ErrSessionNotFound,
		Message:    "Session not found",
		StatusCode: http.StatusNotFound,
	}).WithMetadata("session_id", sessionID)
}

// SessionExpired creates a session expired error
func SessionExpired(sessionID string) *AppError {
	return (&AppError{
		Code:       ErrSessionExpired,
		Message:    "Session has expired",
		StatusCode: http.StatusUnauthorized,
	}).WithMetadata("session_id", sessionID)
}

// InvalidCredentials creates an invalid credentials error
func InvalidCredentials() *AppError {
	return &AppError{
		Code:       ErrInvalidCredentials,
		Message:    "Invalid username or password",
		StatusCode: http.StatusUnauthorized,
	}
}

// InvalidToken creates an invalid token error
func InvalidToken(details string) *AppError {
	return &AppError{
		Code:       ErrInvalidToken,
		Message:    "Invalid authentication token",
		Details:    details,
		StatusCode: http.StatusUnauthorized,
	}
}

// TokenExpired creates a token expired error
func TokenExpired() *AppError {
	return &AppError{
		Code:       ErrTokenExpired,
		Message:    "Authentication token has expired",
		StatusCode: http.StatusUnauthorized,
	}
}

// InsufficientPermissions creates an insufficient permissions error
func InsufficientPermissions(action string) *AppError {
	return (&AppError{
		Code:       ErrInsufficientPerms,
		Message:    "Insufficient permissions to perform this action",
		StatusCode: http.StatusForbidden,
	}).WithMetadata("action", action)
}

// PolicyNotFound creates a policy not found error
func PolicyNotFound(policyID string) *AppError {
	return (&AppError{
		Code:       ErrPolicyNotFound,
		Message:    "Policy not found",
		StatusCode: http.StatusNotFound,
	}).WithMetadata("policy_id", policyID)
}

// PolicyViolation creates a policy violation error
func PolicyViolation(policyName, reason string) *AppError {
	return (&AppError{
		Code:       ErrPolicyViolation,
		Message:    fmt.Sprintf("Policy violation: %s", policyName),
		Details:    reason,
		StatusCode: http.StatusForbidden,
	}).WithMetadata("policy", policyName)
}

// DatabaseError creates a database error
func DatabaseError(operation string, err error) *AppError {
	return &AppError{
		Code:       ErrDatabase,
		Message:    "Database operation failed",
		Details:    operation,
		StatusCode: http.StatusInternalServerError,
		Err:        err,
	}
}

// DuplicateKey creates a duplicate key error
func DuplicateKey(key string) *AppError {
	return (&AppError{
		Code:       ErrDuplicateKey,
		Message:    "Duplicate key violation",
		StatusCode: http.StatusConflict,
	}).WithMetadata("key", key)
}

// ErrorResponse is the JSON response structure for errors
type ErrorResponse struct {
	Error      ErrorCode              `json:"error"`
	Message    string                 `json:"message"`
	Details    string                 `json:"details,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	RequestID  string                 `json:"request_id,omitempty"`
	Timestamp  string                 `json:"timestamp,omitempty"`
}

// HandleError sends an error response to the client
func HandleError(c *gin.Context, err error) {
	var appErr *AppError
	var ok bool

	// Check if it's an AppError
	if appErr, ok = err.(*AppError); !ok {
		// If not, wrap it as an internal error
		appErr = Internal("An unexpected error occurred", err)
	}

	// Get request ID from context
	requestID, _ := c.Get("request_id")
	reqIDStr, _ := requestID.(string)

	// Build error response
	response := ErrorResponse{
		Error:     appErr.Code,
		Message:   appErr.Message,
		Details:   appErr.Details,
		Metadata:  appErr.Metadata,
		RequestID: reqIDStr,
	}

	// Set status code and send response
	c.JSON(appErr.StatusCode, response)
}

// ErrorHandler is a middleware that handles panics and converts them to errors
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				var appErr *AppError

				switch e := err.(type) {
				case *AppError:
					appErr = e
				case error:
					appErr = Internal("Internal server error", e)
				default:
					appErr = Internal("Internal server error", fmt.Errorf("%v", err))
				}

				HandleError(c, appErr)
				c.Abort()
			}
		}()

		c.Next()
	}
}

// IsErrorCode checks if an error has a specific error code
func IsErrorCode(err error, code ErrorCode) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code == code
	}
	return false
}

// GetStatusCode returns the HTTP status code for an error
func GetStatusCode(err error) int {
	if appErr, ok := err.(*AppError); ok {
		return appErr.StatusCode
	}
	return http.StatusInternalServerError
}
