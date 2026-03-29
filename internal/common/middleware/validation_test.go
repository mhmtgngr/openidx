// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ========================================
// Test Helper Functions
// ========================================

func setupTestRouter(middlewares ...gin.HandlerFunc) *gin.Engine {
	router := gin.New()
	for _, m := range middlewares {
		router.Use(m)
	}
	router.POST("/test", func(c *gin.Context) {
		body := GetValidatedBody(c)
		c.JSON(http.StatusOK, gin.H{
			"message": "success",
			"body":    body,
		})
	})
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	router.GET("/test/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": c.Param("id")})
	})
	return router
}

// ========================================
// MaxBodySize Tests
// ========================================

func TestMaxBodySize_ValidBody(t *testing.T) {
	router := setupTestRouter(MaxBodySize(1024))
	body := []byte(`{"test": "data"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMaxBodySize_BodyExceedsLimit(t *testing.T) {
	router := setupTestRouter(MaxBodySize(100))
	largeBody := bytes.Repeat([]byte("a"), 101)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestMaxBodySize_ContentLengthHeader(t *testing.T) {
	router := setupTestRouter(MaxBodySize(100))
	body := []byte(`{"test": "data"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "1000") // Claim large size
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

// ========================================
// ValidateContentType Tests
// ========================================

func TestValidateContentType_AllowedType(t *testing.T) {
	router := setupTestRouter(ValidateContentType([]string{"application/json"}))
	body := []byte(`{"test": "data"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateContentType_UnsupportedType(t *testing.T) {
	router := setupTestRouter(ValidateContentType([]string{"application/json"}))
	body := []byte(`<xml>data</xml>`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)
}

func TestValidateContentType_WithCharset(t *testing.T) {
	router := setupTestRouter(ValidateContentType([]string{"application/json"}))
	body := []byte(`{"test": "data"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateContentType_SkipsGET(t *testing.T) {
	router := setupTestRouter(ValidateContentType([]string{"application/json"}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateContentType_CaseInsensitive(t *testing.T) {
	router := setupTestRouter(ValidateContentType([]string{"application/json"}))
	body := []byte(`{"test": "data"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "Application/JSON")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateContentType_MultipleAllowed(t *testing.T) {
	router := setupTestRouter(ValidateContentType([]string{"application/json", "application/xml"}))
	body := []byte(`{"test": "data"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ========================================
// RequireHeaders Tests
// ========================================

func TestRequireHeaders_AllPresent(t *testing.T) {
	router := setupTestRouter(RequireHeaders([]string{"X-Required-1", "X-Required-2"}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Required-1", "value1")
	req.Header.Set("X-Required-2", "value2")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireHeaders_MissingHeader(t *testing.T) {
	router := setupTestRouter(RequireHeaders([]string{"X-Required-1", "X-Required-2"}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Required-1", "value1")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRequireHeaders_EmptyHeaderValue(t *testing.T) {
	router := setupTestRouter(RequireHeaders([]string{"X-Required"}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Required", "")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ========================================
// ValidateJSONSchema Tests
// ========================================

func TestValidateJSONSchema_ValidObject(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"email", "name"},
		Properties: map[string]*JSONSchema{
			"email": {Type: "string", Format: "email"},
			"name":  {Type: "string", MinLength: intPtr(1)},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))
	body := []byte(`{"email": "test@example.com", "name": "John Doe"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateJSONSchema_MissingRequiredField(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"email", "name"},
		Properties: map[string]*JSONSchema{
			"email": {Type: "string", Format: "email"},
			"name":  {Type: "string"},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))
	body := []byte(`{"email": "test@example.com"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestValidateJSONSchema_InvalidEmailFormat(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"email"},
		Properties: map[string]*JSONSchema{
			"email": {Type: "string", Format: "email"},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))
	body := []byte(`{"email": "not-an-email"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestValidateJSONSchema_StringLengthValidation(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"name"},
		Properties: map[string]*JSONSchema{
			"name": {Type: "string", MinLength: intPtr(3), MaxLength: intPtr(10)},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))

	// Test too short
	body := []byte(`{"name": "ab"}`)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Test too long
	body = []byte(`{"name": "this is way too long"}`)
	req = httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Test valid
	body = []byte(`{"name": "John"}`)
	req = httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateJSONSchema_EnumValidation(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"status"},
		Properties: map[string]*JSONSchema{
			"status": {Type: "string", Enum: []interface{}{"active", "inactive", "pending"}},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))

	// Test invalid enum value
	body := []byte(`{"status": "deleted"}`)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Test valid enum value
	body = []byte(`{"status": "active"}`)
	req = httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateJSONSchema_NestedObjects(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"user"},
		Properties: map[string]*JSONSchema{
			"user": {
				Type:     "object",
				Required: []string{"email"},
				Properties: map[string]*JSONSchema{
					"email": {Type: "string", Format: "email"},
				},
			},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))

	// Test nested validation
	body := []byte(`{"user": {"email": "invalid"}}`)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Test valid nested
	body = []byte(`{"user": {"email": "test@example.com"}}`)
	req = httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateJSONSchema_ArrayValidation(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"tags"},
		Properties: map[string]*JSONSchema{
			"tags": {
				Type:      "array",
				MinLength: intPtr(1),
				MaxLength: intPtr(5),
				Items:     &JSONSchema{Type: "string"},
			},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))

	// Test empty array
	body := []byte(`{"tags": []}`)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Test valid array
	body = []byte(`{"tags": ["tag1", "tag2"]}`)
	req = httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateJSONSchema_NumberValidation(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"age"},
		Properties: map[string]*JSONSchema{
			"age": {
				Type:    "integer",
				Minimum: floatPtr(18),
				Maximum: floatPtr(120),
			},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))

	// Test below minimum
	body := []byte(`{"age": 17}`)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Test non-integer
	body = []byte(`{"age": 25.5}`)
	req = httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Test valid
	body = []byte(`{"age": 25}`)
	req = httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateJSONSchema_InvalidJSON(t *testing.T) {
	schema := &JSONSchema{Type: "object"}
	router := setupTestRouter(ValidateJSONSchema(schema))
	body := []byte(`{invalid json}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidateJSONSchema_SkipsGET(t *testing.T) {
	schema := &JSONSchema{Type: "object"}
	router := setupTestRouter(ValidateJSONSchema(schema))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateJSONSchema_UUIDFormat(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"id"},
		Properties: map[string]*JSONSchema{
			"id": {Type: "string", Format: "uuid"},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))

	// Test invalid UUID
	body := []byte(`{"id": "not-a-uuid"}`)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Test valid UUID
	body = []byte(`{"id": "550e8400-e29b-41d4-a716-446655440000"}`)
	req = httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetValidatedBodyMap(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"test"},
		Properties: map[string]*JSONSchema{
			"test": {Type: "string"},
		},
	}

	handlerCalled := false
	router := gin.New()
	router.Use(ValidateJSONSchema(schema))
	router.POST("/test", func(c *gin.Context) {
		body := GetValidatedBodyMap(c)
		require.NotNil(t, body)
		assert.Equal(t, "value", body["test"])
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{})
	})

	body := []byte(`{"test": "value"}`)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
}

// ========================================
// ValidateQueryParams Tests
// ========================================

func TestValidateQueryParams_ValidParams(t *testing.T) {
	validators := map[string]ValidationRule{
		"email": {Validators: []Validator{ValidateEmail()}},
		"age":   {Validators: []Validator{ValidateInt(), ValidateRange(1, 120)}},
	}
	router := setupTestRouter(ValidateQueryParams(validators))

	req := httptest.NewRequest("GET", "/test?email=test@example.com&age=25", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateQueryParams_InvalidEmail(t *testing.T) {
	validators := map[string]ValidationRule{
		"email": {Validators: []Validator{ValidateEmail()}},
	}
	router := setupTestRouter(ValidateQueryParams(validators))

	req := httptest.NewRequest("GET", "/test?email=not-an-email", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidateQueryParams_OutOfRange(t *testing.T) {
	validators := map[string]ValidationRule{
		"age": {Validators: []Validator{ValidateInt(), ValidateRange(1, 120)}},
	}
	router := setupTestRouter(ValidateQueryParams(validators))

	req := httptest.NewRequest("GET", "/test?age=150", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidateQueryParams_MissingRequired(t *testing.T) {
	validators := map[string]ValidationRule{
		"required": {Required: true, Validators: []Validator{ValidateEmail()}},
	}
	router := setupTestRouter(ValidateQueryParams(validators))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidateQueryParams_MultipleValues(t *testing.T) {
	validators := map[string]ValidationRule{
		"tag": {Validators: []Validator{ValidateMaxLength(10)}},
	}
	router := setupTestRouter(ValidateQueryParams(validators))

	req := httptest.NewRequest("GET", "/test?tag=tag1&tag=tag2", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateQueryParams_EnumValidation(t *testing.T) {
	validators := map[string]ValidationRule{
		"status": {Validators: []Validator{ValidateEnum([]string{"active", "inactive"})}},
	}
	router := setupTestRouter(ValidateQueryParams(validators))

	req := httptest.NewRequest("GET", "/test?status=deleted", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidateQueryParams_UUIDValidation(t *testing.T) {
	validators := map[string]ValidationRule{
		"id": {Validators: []Validator{ValidateUUID()}},
	}
	router := setupTestRouter(ValidateQueryParams(validators))

	req := httptest.NewRequest("GET", "/test?id=not-a-uuid", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ========================================
// ValidatePathParams Tests
// ========================================

func TestValidatePathParams_ValidParam(t *testing.T) {
	validators := map[string]ValidationRule{
		"id": {Validators: []Validator{ValidateUUID()}},
	}
	router := setupTestRouter(ValidatePathParams(validators))

	req := httptest.NewRequest("GET", "/test/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidatePathParams_InvalidParam(t *testing.T) {
	validators := map[string]ValidationRule{
		"id": {Validators: []Validator{ValidateUUID()}},
	}
	router := setupTestRouter(ValidatePathParams(validators))

	req := httptest.NewRequest("GET", "/test/invalid-id", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidatePathParams_IntegerParam(t *testing.T) {
	validators := map[string]ValidationRule{
		"id": {Validators: []Validator{ValidateInt()}},
	}
	router := setupTestRouter(ValidatePathParams(validators))

	req := httptest.NewRequest("GET", "/test/abc", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ========================================
// Built-in Validators Tests
// ========================================

func TestValidateEmail_Valid(t *testing.T) {
	validator := ValidateEmail()
	assert.NoError(t, validator("test@example.com"))
	assert.NoError(t, validator("user.name+tag+sorting@example.co.uk"))
}

func TestValidateEmail_Invalid(t *testing.T) {
	validator := ValidateEmail()
	assert.Error(t, validator("not-an-email"))
	assert.Error(t, validator("@example.com"))
	assert.Error(t, validator("test@"))
}

func TestValidateUUID_Valid(t *testing.T) {
	validator := ValidateUUID()
	assert.NoError(t, validator("550e8400-e29b-41d4-a716-446655440000"))
	assert.NoError(t, validator("00000000-0000-0000-0000-000000000000"))
}

func TestValidateUUID_Invalid(t *testing.T) {
	validator := ValidateUUID()
	assert.Error(t, validator("not-a-uuid"))
	assert.Error(t, validator("550e8400-e29b-41d4-a716"))
}

func TestValidateMinLength(t *testing.T) {
	validator := ValidateMinLength(5)
	assert.Error(t, validator("abc"))
	assert.NoError(t, validator("abcdef"))
}

func TestValidateMaxLength(t *testing.T) {
	validator := ValidateMaxLength(5)
	assert.NoError(t, validator("abc"))
	assert.Error(t, validator("abcdef"))
}

func TestValidateRange(t *testing.T) {
	validator := ValidateRange(1, 10)
	assert.Error(t, validator("0"))
	assert.Error(t, validator("11"))
	assert.NoError(t, validator("5"))
	assert.Error(t, validator("abc"))
}

func TestValidateEnum(t *testing.T) {
	validator := ValidateEnum([]string{"a", "b", "c"})
	assert.NoError(t, validator("a"))
	assert.Error(t, validator("d"))
}

func TestValidatePattern(t *testing.T) {
	validator := ValidatePattern(`^[a-z]+$`)
	assert.NoError(t, validator("abc"))
	assert.Error(t, validator("abc123"))
	assert.Error(t, validator("ABC"))
}

func TestValidateInt(t *testing.T) {
	validator := ValidateInt()
	assert.NoError(t, validator("123"))
	assert.NoError(t, validator("-123"))
	assert.Error(t, validator("abc"))
	assert.Error(t, validator("12.3"))
}

func TestValidateBool(t *testing.T) {
	validator := ValidateBool()
	assert.NoError(t, validator("true"))
	assert.NoError(t, validator("false"))
	assert.NoError(t, validator("1"))
	assert.NoError(t, validator("0"))
	assert.Error(t, validator("yes"))
}

func TestValidateDate(t *testing.T) {
	validator := ValidateDate()
	assert.NoError(t, validator("2023-01-15"))
	assert.Error(t, validator("2023-01-15T00:00:00Z"))
	assert.Error(t, validator("15-01-2023"))
}

func TestValidateDateTime(t *testing.T) {
	validator := ValidateDateTime()
	assert.NoError(t, validator("2023-01-15T10:30:00Z"))
	assert.NoError(t, validator("2023-01-15T10:30:00.123Z"))
	assert.Error(t, validator("2023-01-15"))
}

// ========================================
// Predefined Schema Tests
// ========================================

func TestUserCreateSchema_Valid(t *testing.T) {
	router := setupTestRouter(ValidateJSONSchema(UserCreateSchema))
	body := []byte(`{"email": "test@example.com", "name": "John Doe", "password": "securepass"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserCreateSchema_MissingRequired(t *testing.T) {
	router := setupTestRouter(ValidateJSONSchema(UserCreateSchema))
	body := []byte(`{"email": "test@example.com"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestUserCreateSchema_ShortPassword(t *testing.T) {
	router := setupTestRouter(ValidateJSONSchema(UserCreateSchema))
	body := []byte(`{"email": "test@example.com", "name": "John Doe", "password": "short"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestUserCreateSchema_InvalidRole(t *testing.T) {
	router := setupTestRouter(ValidateJSONSchema(UserCreateSchema))
	body := []byte(`{"email": "test@example.com", "name": "John Doe", "role": "superadmin"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

// ========================================
// Pagination Schema Tests
// ========================================

func TestPaginationSchema_Valid(t *testing.T) {
	router := setupTestRouter(ValidateQueryParams(PaginationSchema))

	req := httptest.NewRequest("GET", "/test?page=1&limit=10&sort_order=asc", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPaginationSchema_InvalidPage(t *testing.T) {
	router := setupTestRouter(ValidateQueryParams(PaginationSchema))

	req := httptest.NewRequest("GET", "/test?page=0", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPaginationSchema_InvalidLimit(t *testing.T) {
	router := setupTestRouter(ValidateQueryParams(PaginationSchema))

	req := httptest.NewRequest("GET", "/test?limit=101", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ========================================
// Integration Tests
// ========================================

func TestMultipleValidatorsChained(t *testing.T) {
	router := setupTestRouter(
		ValidateContentType([]string{"application/json"}),
		MaxBodySize(1024),
		ValidateJSONSchema(UserCreateSchema),
	)

	body := []byte(`{"email": "test@example.com", "name": "John Doe"}`)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateJSONSchema_ResponseFormat(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"email"},
		Properties: map[string]*JSONSchema{
			"email": {Type: "string", Format: "email"},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))
	body := []byte(`{"email": "invalid-email"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Contains(t, resp, "error")
	assert.Contains(t, resp, "errors")

	errors, ok := resp["errors"].([]interface{})
	require.True(t, ok)
	assert.Greater(t, len(errors), 0)

	firstError := errors[0].(map[string]interface{})
	assert.Contains(t, firstError, "field")
	assert.Contains(t, firstError, "message")
}

func TestValidateJSONSchema_BooleanType(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"active"},
		Properties: map[string]*JSONSchema{
			"active": {Type: "boolean"},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))

	// Valid boolean
	body := []byte(`{"active": true}`)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Invalid boolean
	body = []byte(`{"active": "yes"}`)
	req = httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestValidateJSONSchema_NullType(t *testing.T) {
	schema := &JSONSchema{
		Type:     "object",
		Required: []string{"field"},
		Properties: map[string]*JSONSchema{
			"field": {Type: "string"},
		},
	}
	router := setupTestRouter(ValidateJSONSchema(schema))

	// Null in required field should fail
	body := []byte(`{"field": null}`)
	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}
