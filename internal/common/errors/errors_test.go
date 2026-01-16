package errors

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	err := New(ErrBadRequest, "Test error", http.StatusBadRequest)

	assert.Equal(t, ErrBadRequest, err.Code)
	assert.Equal(t, "Test error", err.Message)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	assert.Nil(t, err.Err)
}

func TestWrap(t *testing.T) {
	originalErr := errors.New("original error")
	err := Wrap(originalErr, ErrInternal, "Wrapped error", http.StatusInternalServerError)

	assert.Equal(t, ErrInternal, err.Code)
	assert.Equal(t, "Wrapped error", err.Message)
	assert.Equal(t, http.StatusInternalServerError, err.StatusCode)
	assert.Equal(t, originalErr, err.Err)
}

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AppError
		expected string
	}{
		{
			name: "Error without details",
			err: &AppError{
				Code:    ErrBadRequest,
				Message: "Invalid request",
			},
			expected: "[BAD_REQUEST] Invalid request",
		},
		{
			name: "Error with details",
			err: &AppError{
				Code:    ErrBadRequest,
				Message: "Invalid request",
				Details: "Missing field: username",
			},
			expected: "[BAD_REQUEST] Invalid request: Missing field: username",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestAppError_WithMetadata(t *testing.T) {
	err := New(ErrUserNotFound, "User not found", http.StatusNotFound)
	err.WithMetadata("user_id", "123")

	assert.NotNil(t, err.Metadata)
	assert.Equal(t, "123", err.Metadata["user_id"])

	// Add another metadata field
	err.WithMetadata("attempted_at", "2024-01-01")
	assert.Equal(t, 2, len(err.Metadata))
}

func TestAppError_WithDetails(t *testing.T) {
	err := New(ErrBadRequest, "Invalid request", http.StatusBadRequest)
	err.WithDetails("Username cannot be empty")

	assert.Equal(t, "Username cannot be empty", err.Details)
}

func TestAppError_Unwrap(t *testing.T) {
	originalErr := errors.New("original error")
	err := Wrap(originalErr, ErrInternal, "Wrapped error", http.StatusInternalServerError)

	unwrapped := err.Unwrap()
	assert.Equal(t, originalErr, unwrapped)
}

func TestPredefinedErrors(t *testing.T) {
	tests := []struct {
		name           string
		createError    func() *AppError
		expectedCode   ErrorCode
		expectedStatus int
	}{
		{
			name:           "Internal",
			createError:    func() *AppError { return Internal("System error", nil) },
			expectedCode:   ErrInternal,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "NotFound",
			createError:    func() *AppError { return NotFound("User") },
			expectedCode:   ErrNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "BadRequest",
			createError:    func() *AppError { return BadRequest("Invalid input") },
			expectedCode:   ErrBadRequest,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Unauthorized",
			createError:    func() *AppError { return Unauthorized("Not authenticated") },
			expectedCode:   ErrUnauthorized,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Forbidden",
			createError:    func() *AppError { return Forbidden("Access denied") },
			expectedCode:   ErrForbidden,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Conflict",
			createError:    func() *AppError { return Conflict("Resource exists") },
			expectedCode:   ErrConflict,
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "ValidationError",
			createError:    func() *AppError { return ValidationError("Validation failed") },
			expectedCode:   ErrValidation,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Timeout",
			createError:    func() *AppError { return Timeout("Request timeout") },
			expectedCode:   ErrTimeout,
			expectedStatus: http.StatusGatewayTimeout,
		},
		{
			name:           "RateLimit",
			createError:    func() *AppError { return RateLimit("Too many requests") },
			expectedCode:   ErrRateLimit,
			expectedStatus: http.StatusTooManyRequests,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.createError()
			assert.Equal(t, tt.expectedCode, err.Code)
			assert.Equal(t, tt.expectedStatus, err.StatusCode)
		})
	}
}

func TestResourceSpecificErrors(t *testing.T) {
	t.Run("UserNotFound", func(t *testing.T) {
		err := UserNotFound("user-123")
		assert.Equal(t, ErrUserNotFound, err.Code)
		assert.Equal(t, http.StatusNotFound, err.StatusCode)
		assert.Equal(t, "user-123", err.Metadata["user_id"])
	})

	t.Run("UserAlreadyExists", func(t *testing.T) {
		err := UserAlreadyExists("john.doe")
		assert.Equal(t, ErrUserAlreadyExists, err.Code)
		assert.Equal(t, http.StatusConflict, err.StatusCode)
		assert.Equal(t, "john.doe", err.Metadata["username"])
	})

	t.Run("UserDisabled", func(t *testing.T) {
		err := UserDisabled("user-123")
		assert.Equal(t, ErrUserDisabled, err.Code)
		assert.Equal(t, http.StatusForbidden, err.StatusCode)
		assert.Equal(t, "user-123", err.Metadata["user_id"])
	})

	t.Run("GroupNotFound", func(t *testing.T) {
		err := GroupNotFound("group-456")
		assert.Equal(t, ErrGroupNotFound, err.Code)
		assert.Equal(t, http.StatusNotFound, err.StatusCode)
		assert.Equal(t, "group-456", err.Metadata["group_id"])
	})

	t.Run("SessionExpired", func(t *testing.T) {
		err := SessionExpired("session-789")
		assert.Equal(t, ErrSessionExpired, err.Code)
		assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
		assert.Equal(t, "session-789", err.Metadata["session_id"])
	})
}

func TestAuthenticationErrors(t *testing.T) {
	t.Run("InvalidCredentials", func(t *testing.T) {
		err := InvalidCredentials()
		assert.Equal(t, ErrInvalidCredentials, err.Code)
		assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		err := InvalidToken("token malformed")
		assert.Equal(t, ErrInvalidToken, err.Code)
		assert.Equal(t, "token malformed", err.Details)
		assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
	})

	t.Run("TokenExpired", func(t *testing.T) {
		err := TokenExpired()
		assert.Equal(t, ErrTokenExpired, err.Code)
		assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
	})

	t.Run("InsufficientPermissions", func(t *testing.T) {
		err := InsufficientPermissions("delete_user")
		assert.Equal(t, ErrInsufficientPerms, err.Code)
		assert.Equal(t, http.StatusForbidden, err.StatusCode)
		assert.Equal(t, "delete_user", err.Metadata["action"])
	})
}

func TestPolicyErrors(t *testing.T) {
	t.Run("PolicyNotFound", func(t *testing.T) {
		err := PolicyNotFound("policy-123")
		assert.Equal(t, ErrPolicyNotFound, err.Code)
		assert.Equal(t, http.StatusNotFound, err.StatusCode)
		assert.Equal(t, "policy-123", err.Metadata["policy_id"])
	})

	t.Run("PolicyViolation", func(t *testing.T) {
		err := PolicyViolation("MFA_Required", "User must have MFA enabled")
		assert.Equal(t, ErrPolicyViolation, err.Code)
		assert.Equal(t, http.StatusForbidden, err.StatusCode)
		assert.Equal(t, "MFA_Required", err.Metadata["policy"])
		assert.Contains(t, err.Message, "MFA_Required")
		assert.Equal(t, "User must have MFA enabled", err.Details)
	})
}

func TestDatabaseErrors(t *testing.T) {
	t.Run("DatabaseError", func(t *testing.T) {
		originalErr := errors.New("connection timeout")
		err := DatabaseError("insert user", originalErr)
		assert.Equal(t, ErrDatabase, err.Code)
		assert.Equal(t, http.StatusInternalServerError, err.StatusCode)
		assert.Equal(t, "insert user", err.Details)
		assert.Equal(t, originalErr, err.Err)
	})

	t.Run("DuplicateKey", func(t *testing.T) {
		err := DuplicateKey("username")
		assert.Equal(t, ErrDuplicateKey, err.Code)
		assert.Equal(t, http.StatusConflict, err.StatusCode)
		assert.Equal(t, "username", err.Metadata["key"])
	})
}

func TestIsErrorCode(t *testing.T) {
	t.Run("Matching error code", func(t *testing.T) {
		err := UserNotFound("user-123")
		assert.True(t, IsErrorCode(err, ErrUserNotFound))
	})

	t.Run("Non-matching error code", func(t *testing.T) {
		err := UserNotFound("user-123")
		assert.False(t, IsErrorCode(err, ErrBadRequest))
	})

	t.Run("Non-AppError", func(t *testing.T) {
		err := errors.New("standard error")
		assert.False(t, IsErrorCode(err, ErrInternal))
	})
}

func TestGetStatusCode(t *testing.T) {
	t.Run("AppError status code", func(t *testing.T) {
		err := BadRequest("Invalid input")
		assert.Equal(t, http.StatusBadRequest, GetStatusCode(err))
	})

	t.Run("Non-AppError returns 500", func(t *testing.T) {
		err := errors.New("standard error")
		assert.Equal(t, http.StatusInternalServerError, GetStatusCode(err))
	})
}

func TestErrorChaining(t *testing.T) {
	t.Run("Chain multiple errors", func(t *testing.T) {
		// Create a chain of errors
		baseErr := errors.New("connection refused")
		dbErr := Wrap(baseErr, ErrDatabase, "Failed to connect", http.StatusInternalServerError)
		appErr := Wrap(dbErr, ErrInternal, "Service unavailable", http.StatusServiceUnavailable)

		// Verify we can unwrap the chain
		assert.Equal(t, dbErr, appErr.Unwrap())
		assert.Equal(t, baseErr, dbErr.Unwrap())
	})
}

func TestErrorMetadataChaining(t *testing.T) {
	err := UserNotFound("user-123")
	err.WithMetadata("action", "login")
	err.WithMetadata("ip", "192.168.1.1")
	err.WithDetails("User account may have been deleted")

	assert.Equal(t, 3, len(err.Metadata))
	assert.Equal(t, "user-123", err.Metadata["user_id"])
	assert.Equal(t, "login", err.Metadata["action"])
	assert.Equal(t, "192.168.1.1", err.Metadata["ip"])
	assert.Equal(t, "User account may have been deleted", err.Details)
}

// Benchmark tests
func BenchmarkNewError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New(ErrBadRequest, "Test error", http.StatusBadRequest)
	}
}

func BenchmarkWrapError(b *testing.B) {
	originalErr := errors.New("original error")
	for i := 0; i < b.N; i++ {
		_ = Wrap(originalErr, ErrInternal, "Wrapped error", http.StatusInternalServerError)
	}
}

func BenchmarkUserNotFound(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = UserNotFound("user-123")
	}
}

func BenchmarkWithMetadata(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := New(ErrBadRequest, "Test", http.StatusBadRequest)
		err.WithMetadata("key", "value")
	}
}
