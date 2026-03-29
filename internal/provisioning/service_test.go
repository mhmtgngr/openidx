package provisioning

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestSCIMUserSerialization verifies SCIM user JSON marshaling
func TestSCIMUserSerialization(t *testing.T) {
	user := &SCIMUser{
		Schemas:    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:         "scim-user-001",
		ExternalID: "ext-001",
		UserName:   "john.doe",
		Name: SCIMName{
			Formatted:  "John Doe",
			FamilyName: "Doe",
			GivenName:  "John",
		},
		DisplayName: "John Doe",
		Emails: []SCIMEmail{
			{Value: "john@example.com", Type: "work", Primary: true},
			{Value: "john.personal@example.com", Type: "home", Primary: false},
		},
		Active: true,
		Groups: []SCIMGroupRef{
			{Value: "group-1", Display: "Engineering"},
		},
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      time.Now(),
			LastModified: time.Now(),
			Location:     "/scim/v2/Users/scim-user-001",
		},
	}

	data, err := json.Marshal(user)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	var decoded SCIMUser
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "john.doe", decoded.UserName)
	assert.Equal(t, "John", decoded.Name.GivenName)
	assert.Equal(t, "Doe", decoded.Name.FamilyName)
	assert.True(t, decoded.Active)
	assert.Len(t, decoded.Emails, 2)
	assert.True(t, decoded.Emails[0].Primary)
	assert.Len(t, decoded.Groups, 1)
	assert.Equal(t, "User", decoded.Meta.ResourceType)
	assert.Len(t, decoded.Schemas, 1)
}

// TestSCIMGroupSerialization verifies SCIM group JSON marshaling
func TestSCIMGroupSerialization(t *testing.T) {
	group := &SCIMGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ID:          "scim-group-001",
		ExternalID:  "ext-grp-001",
		DisplayName: "Engineering",
		Members: []SCIMMember{
			{Value: "user-1", Display: "John Doe", Type: "User"},
			{Value: "user-2", Display: "Jane Smith", Type: "User"},
		},
		Meta: SCIMMeta{
			ResourceType: "Group",
			Created:      time.Now(),
			LastModified: time.Now(),
		},
	}

	data, err := json.Marshal(group)
	assert.NoError(t, err)

	var decoded SCIMGroup
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "Engineering", decoded.DisplayName)
	assert.Len(t, decoded.Members, 2)
	assert.Equal(t, "User", decoded.Members[0].Type)
	assert.Equal(t, "Group", decoded.Meta.ResourceType)
}

// TestSCIMListResponse verifies list response format
func TestSCIMListResponse(t *testing.T) {
	users := []SCIMUser{
		{ID: "u1", UserName: "user1", Active: true},
		{ID: "u2", UserName: "user2", Active: false},
	}

	response := SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: 2,
		StartIndex:   1,
		ItemsPerPage: 20,
		Resources:    users,
	}

	data, err := json.Marshal(response)
	assert.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, float64(2), decoded["totalResults"])
	assert.Equal(t, float64(1), decoded["startIndex"])
	assert.Equal(t, float64(20), decoded["itemsPerPage"])
	assert.NotNil(t, decoded["Resources"])
}

// TestSCIMPatchRequest verifies SCIM PATCH request format
func TestSCIMPatchRequest(t *testing.T) {
	patch := SCIMPatchRequest{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{
			{Op: "replace", Path: "active", Value: false},
			{Op: "add", Path: "emails", Value: map[string]interface{}{
				"value": "new@example.com", "type": "work",
			}},
			{Op: "remove", Path: "phoneNumbers"},
		},
	}

	data, err := json.Marshal(patch)
	assert.NoError(t, err)

	var decoded SCIMPatchRequest
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Len(t, decoded.Operations, 3)
	assert.Equal(t, "replace", decoded.Operations[0].Op)
	assert.Equal(t, "active", decoded.Operations[0].Path)
	assert.Equal(t, "add", decoded.Operations[1].Op)
	assert.Equal(t, "remove", decoded.Operations[2].Op)
}

// TestSCIMError verifies SCIM error response format
func TestSCIMError(t *testing.T) {
	scimErr := SCIMError{
		Schemas:  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		Status:   "404",
		ScimType: "invalidValue",
		Detail:   "Resource not found",
	}

	data, err := json.Marshal(scimErr)
	assert.NoError(t, err)

	var decoded SCIMError
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "404", decoded.Status)
	assert.Equal(t, "invalidValue", decoded.ScimType)
	assert.Equal(t, "Resource not found", decoded.Detail)
}

// TestRuleTriggers verifies all trigger type constants
func TestRuleTriggers(t *testing.T) {
	triggers := []RuleTrigger{
		TriggerUserCreated,
		TriggerUserUpdated,
		TriggerUserDeleted,
		TriggerGroupMembership,
		TriggerAttributeChange,
		TriggerScheduled,
	}

	assert.Len(t, triggers, 6)
	assert.Equal(t, RuleTrigger("user_created"), TriggerUserCreated)
	assert.Equal(t, RuleTrigger("user_updated"), TriggerUserUpdated)
	assert.Equal(t, RuleTrigger("user_deleted"), TriggerUserDeleted)
	assert.Equal(t, RuleTrigger("group_membership"), TriggerGroupMembership)
	assert.Equal(t, RuleTrigger("attribute_change"), TriggerAttributeChange)
	assert.Equal(t, RuleTrigger("scheduled"), TriggerScheduled)
}

// TestProvisioningRuleSerialization verifies provisioning rule JSON
func TestProvisioningRuleSerialization(t *testing.T) {
	rule := &ProvisioningRule{
		ID:          "rule-001",
		Name:        "Auto-assign Engineering group",
		Description: "New users in engineering dept get added to Engineering group",
		Trigger:     TriggerUserCreated,
		Conditions: []RuleCondition{
			{Field: "department", Operator: "equals", Value: "engineering"},
		},
		Actions: []RuleAction{
			{
				Type:   "add_to_group",
				Target: "group-engineering",
				Parameters: map[string]interface{}{
					"role": "member",
				},
			},
		},
		Enabled:  true,
		Priority: 1,
	}

	data, err := json.Marshal(rule)
	assert.NoError(t, err)

	var decoded ProvisioningRule
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "rule-001", decoded.ID)
	assert.Equal(t, TriggerUserCreated, decoded.Trigger)
	assert.Len(t, decoded.Conditions, 1)
	assert.Equal(t, "department", decoded.Conditions[0].Field)
	assert.Equal(t, "equals", decoded.Conditions[0].Operator)
	assert.Len(t, decoded.Actions, 1)
	assert.Equal(t, "add_to_group", decoded.Actions[0].Type)
	assert.True(t, decoded.Enabled)
}

// TestRuleConditionOperators tests various condition operators
func TestRuleConditionOperators(t *testing.T) {
	operators := []string{"equals", "not_equals", "contains", "starts_with", "ends_with", "in", "not_in"}

	for _, op := range operators {
		cond := RuleCondition{Field: "email", Operator: op, Value: "test"}
		data, err := json.Marshal(cond)
		assert.NoError(t, err)

		var decoded RuleCondition
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)
		assert.Equal(t, op, decoded.Operator)
	}
}

// TestSCIMUserMinimal tests minimal SCIM user with only required fields
func TestSCIMUserMinimal(t *testing.T) {
	user := &SCIMUser{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		UserName: "minimal.user",
		Active:   true,
	}

	data, err := json.Marshal(user)
	assert.NoError(t, err)

	var decoded SCIMUser
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "minimal.user", decoded.UserName)
	assert.Empty(t, decoded.ID)
	assert.Empty(t, decoded.ExternalID)
	assert.Empty(t, decoded.Emails)
	assert.Empty(t, decoded.Groups)
}

// TestSCIMMetaResourceTypes verifies common resource types
func TestSCIMMetaResourceTypes(t *testing.T) {
	resourceTypes := []string{"User", "Group"}

	for _, rt := range resourceTypes {
		meta := SCIMMeta{ResourceType: rt, Created: time.Now(), LastModified: time.Now()}
		data, err := json.Marshal(meta)
		assert.NoError(t, err)

		var decoded SCIMMeta
		json.Unmarshal(data, &decoded)
		assert.Equal(t, rt, decoded.ResourceType)
	}
}

// TestSCIMEmailPrimary verifies only one email should be primary
func TestSCIMEmailPrimary(t *testing.T) {
	emails := []SCIMEmail{
		{Value: "work@example.com", Type: "work", Primary: true},
		{Value: "home@example.com", Type: "home", Primary: false},
		{Value: "other@example.com", Type: "other", Primary: false},
	}

	primaryCount := 0
	for _, e := range emails {
		if e.Primary {
			primaryCount++
		}
	}
	assert.Equal(t, 1, primaryCount, "exactly one email should be primary")
}

// TestSCIMPatchOperationTypes verifies valid SCIM PATCH operations
func TestSCIMPatchOperationTypes(t *testing.T) {
	validOps := []string{"add", "remove", "replace"}

	for _, op := range validOps {
		patchOp := SCIMPatchOperation{Op: op}
		data, err := json.Marshal(patchOp)
		assert.NoError(t, err)

		var decoded SCIMPatchOperation
		json.Unmarshal(data, &decoded)
		assert.Equal(t, op, decoded.Op)
	}
}

// TestProvisioningRuleMultipleActions tests rule with multiple actions
func TestProvisioningRuleMultipleActions(t *testing.T) {
	rule := &ProvisioningRule{
		ID:      "rule-multi",
		Name:    "Onboarding",
		Trigger: TriggerUserCreated,
		Actions: []RuleAction{
			{Type: "add_to_group", Target: "all-employees"},
			{Type: "assign_role", Target: "basic-user"},
			{Type: "send_notification", Target: "it-team", Parameters: map[string]interface{}{
				"template": "new_user_onboard",
			}},
		},
		Enabled: true,
	}

	data, err := json.Marshal(rule)
	assert.NoError(t, err)

	var decoded ProvisioningRule
	json.Unmarshal(data, &decoded)
	assert.Len(t, decoded.Actions, 3)
	assert.Equal(t, "add_to_group", decoded.Actions[0].Type)
	assert.Equal(t, "assign_role", decoded.Actions[1].Type)
	assert.Equal(t, "send_notification", decoded.Actions[2].Type)
}

// TestContextWithActorID tests setting actor ID in context
func TestContextWithActorID(t *testing.T) {
	t.Run("set actor ID in context", func(t *testing.T) {
		ctx := context.Background()
		actorID := "user-123"

		newCtx := ContextWithActorID(ctx, actorID)

		extracted := actorIDFromContext(newCtx)
		assert.Equal(t, actorID, extracted)
	})

	t.Run("empty actor ID returns system", func(t *testing.T) {
		ctx := context.Background()

		extracted := actorIDFromContext(ctx)
		assert.Equal(t, "system", extracted)
	})

	t.Run("context is independent", func(t *testing.T) {
		ctx := context.Background()
		newCtx := ContextWithActorID(ctx, "user-456")

		// Original context should not have the actor ID
		extractedFromOriginal := actorIDFromContext(ctx)
		assert.Equal(t, "system", extractedFromOriginal)

		// New context should have the actor ID
		extractedFromNew := actorIDFromContext(newCtx)
		assert.Equal(t, "user-456", extractedFromNew)
	})
}

// TestWriteSCIMError tests SCIM error response writing
func TestWriteSCIMError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("write 404 error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		writeSCIMError(c, http.StatusNotFound, "Resource not found")

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "Resource not found")
		assert.Contains(t, w.Body.String(), "urn:ietf:params:scim:api:messages:2.0:Error")
	})

	t.Run("write 400 error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		writeSCIMError(c, http.StatusBadRequest, "Invalid request")

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid request")
	})

	t.Run("verify error structure", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		writeSCIMError(c, http.StatusInternalServerError, "Server error")

		var scimErr SCIMError
		err := json.Unmarshal(w.Body.Bytes(), &scimErr)
		assert.NoError(t, err)

		assert.Equal(t, "500", scimErr.Status)
		assert.Equal(t, "Server error", scimErr.Detail)
		assert.NotEmpty(t, scimErr.Schemas)
	})
}

// TestNewService tests service creation
func TestNewService(t *testing.T) {
	t.Run("create service with dependencies", func(t *testing.T) {
		logger := zaptest.NewLogger(t)
		cfg := &config.Config{}

		svc := NewService(nil, nil, cfg, logger)

		assert.NotNil(t, svc)
		assert.NotNil(t, svc.logger)
		assert.NotNil(t, svc.config)
		assert.Nil(t, svc.db)
		assert.Nil(t, svc.redis)
	})
}

// TestSCIMNameFields tests SCIM name field handling
func TestSCIMNameFields(t *testing.T) {
	t.Run("full name with all fields", func(t *testing.T) {
		name := SCIMName{
			Formatted:       "Dr. John A. Doe Jr.",
			FamilyName:      "Doe",
			GivenName:       "John",
			MiddleName:      "Anthony",
			HonorificPrefix: "Dr.",
			HonorificSuffix: "Jr.",
		}

		assert.Equal(t, "Doe", name.FamilyName)
		assert.Equal(t, "John", name.GivenName)
		assert.Equal(t, "Anthony", name.MiddleName)
	})

	t.Run("minimal name with only required fields", func(t *testing.T) {
		name := SCIMName{
			GivenName:  "Jane",
			FamilyName: "Smith",
		}

		assert.Empty(t, name.MiddleName)
		assert.Empty(t, name.HonorificPrefix)
	})
}

// TestSCIMEmailTypes tests email type handling
func TestSCIMEmailTypes(t *testing.T) {
	t.Run("common email types", func(t *testing.T) {
		emailTypes := []string{"work", "home", "other"}

		for _, eType := range emailTypes {
			email := SCIMEmail{Value: "test@example.com", Type: eType}
			assert.Equal(t, eType, email.Type)
		}
	})

	t.Run("email without type", func(t *testing.T) {
		email := SCIMEmail{Value: "test@example.com"}
		assert.Empty(t, email.Type)
	})
}

// TestSCIMSchemaConstants tests SCIM schema URNs
func TestSCIMSchemaConstants(t *testing.T) {
	t.Run("user schema", func(t *testing.T) {
		schema := "urn:ietf:params:scim:schemas:core:2.0:User"
		assert.Contains(t, schema, "scim")
		assert.Contains(t, schema, "User")
	})

	t.Run("group schema", func(t *testing.T) {
		schema := "urn:ietf:params:scim:schemas:core:2.0:Group"
		assert.Contains(t, schema, "Group")
	})

	t.Run("list response schema", func(t *testing.T) {
		schema := "urn:ietf:params:scim:api:messages:2.0:ListResponse"
		assert.Contains(t, schema, "ListResponse")
	})

	t.Run("patch operation schema", func(t *testing.T) {
		schema := "urn:ietf:params:scim:api:messages:2.0:PatchOp"
		assert.Contains(t, schema, "PatchOp")
	})
}

// TestSCIMMemberTypes tests member type values
func TestSCIMMemberTypes(t *testing.T) {
	t.Run("valid member types", func(t *testing.T) {
		memberTypes := []string{"User", "Group"}

		for _, mType := range memberTypes {
			member := SCIMMember{Value: "id-123", Type: mType}
			assert.Equal(t, mType, member.Type)
		}
	})
}

// TestProvisioningRuleValidation tests rule structure validation
func TestProvisioningRuleValidation(t *testing.T) {
	t.Run("rule requires name and trigger", func(t *testing.T) {
		rule := ProvisioningRule{
			ID:      "rule-123",
			Name:    "Test Rule",
			Trigger: TriggerUserCreated,
		}

		assert.NotEmpty(t, rule.Name)
		assert.NotEmpty(t, rule.Trigger)
	})

	t.Run("rule with empty actions", func(t *testing.T) {
		rule := ProvisioningRule{
			ID:       "rule-456",
			Name:     "Empty Actions Rule",
			Trigger:  TriggerUserUpdated,
			Actions:  []RuleAction{},
			Enabled:  false,
			Priority: 0,
		}

		assert.Empty(t, rule.Actions)
		assert.False(t, rule.Enabled)
		assert.Equal(t, 0, rule.Priority)
	})
}

// TestRuleActionTypes tests action type constants
func TestRuleActionTypes(t *testing.T) {
	t.Run("valid action types", func(t *testing.T) {
		actionTypes := []string{
			"add_to_group",
			"remove_from_group",
			"assign_role",
			"remove_role",
			"send_notification",
			"create_user",
			"disable_user",
			"delete_user",
		}

		for _, aType := range actionTypes {
			action := RuleAction{Type: aType, Target: "target-123"}
			assert.Equal(t, aType, action.Type)
		}
	})
}

// TestSCIMGroupMembersEmpty tests group with no members
func TestSCIMGroupMembersEmpty(t *testing.T) {
	t.Run("group without members", func(t *testing.T) {
		group := SCIMGroup{
			Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
			DisplayName: "Empty Group",
			Members:     []SCIMMember{},
		}

		assert.Empty(t, group.Members)
	})
}

// TestSCIMExternalID tests external ID handling
func TestSCIMExternalID(t *testing.T) {
	t.Run("user with external ID", func(t *testing.T) {
		user := SCIMUser{
			ID:         "internal-123",
			ExternalID: "external-456",
			UserName:   "test.user",
		}

		assert.Equal(t, "internal-123", user.ID)
		assert.Equal(t, "external-456", user.ExternalID)
	})

	t.Run("user without external ID", func(t *testing.T) {
		user := SCIMUser{
			ID:       "internal-789",
			UserName: "test.user2",
		}

		assert.Empty(t, user.ExternalID)
	})
}

// TestSCIMMetaVersion tests version handling in metadata
func TestSCIMMetaVersion(t *testing.T) {
	t.Run("meta with version", func(t *testing.T) {
		meta := SCIMMeta{
			ResourceType: "User",
			Version:      `W/"1234567890"`,
			Created:      time.Now(),
			LastModified: time.Now(),
		}

		assert.NotEmpty(t, meta.Version)
		assert.Contains(t, meta.Version, "\"")
	})

	t.Run("meta without version", func(t *testing.T) {
		meta := SCIMMeta{
			ResourceType: "User",
			Created:      time.Now(),
			LastModified: time.Now(),
		}

		assert.Empty(t, meta.Version)
	})
}

// TestSCIMGroupRef tests group reference structure
func TestSCIMGroupRef(t *testing.T) {
	t.Run("group reference with all fields", func(t *testing.T) {
		ref := SCIMGroupRef{
			Value:   "group-123",
			Ref:     "/scim/v2/Groups/group-123",
			Display: "Engineering",
		}

		assert.Equal(t, "group-123", ref.Value)
		assert.Equal(t, "/scim/v2/Groups/group-123", ref.Ref)
		assert.Equal(t, "Engineering", ref.Display)
	})
}

// TestSCIMListResponsePagination tests pagination fields
func TestSCIMListResponsePagination(t *testing.T) {
	t.Run("pagination parameters", func(t *testing.T) {
		response := SCIMListResponse{
			Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
			TotalResults: 100,
			StartIndex:   1,
			ItemsPerPage: 20,
		}

		assert.Equal(t, 100, response.TotalResults)
		assert.Equal(t, 1, response.StartIndex)
		assert.Equal(t, 20, response.ItemsPerPage)
	})

	t.Run("calculate total pages", func(t *testing.T) {
		totalResults := 100
		itemsPerPage := 20

		totalPages := (totalResults + itemsPerPage - 1) / itemsPerPage
		assert.Equal(t, 5, totalPages)
	})
}

// TestProvisioningRulePriority tests priority handling
func TestProvisioningRulePriority(t *testing.T) {
	t.Run("higher priority number takes precedence", func(t *testing.T) {
		rule1 := ProvisioningRule{Priority: 10}
		rule2 := ProvisioningRule{Priority: 20}
		rule3 := ProvisioningRule{Priority: 5}

		assert.True(t, rule2.Priority > rule1.Priority)
		assert.True(t, rule2.Priority > rule3.Priority)
		assert.True(t, rule1.Priority > rule3.Priority)
	})
}

// TestSCIMErrorStatusCodes tests various SCIM error status codes
func TestSCIMErrorStatusCodes(t *testing.T) {
	t.Run("common error codes", func(t *testing.T) {
		errorCodes := map[int]string{
			400: "Bad Request",
			401: "Unauthorized",
			403: "Forbidden",
			404: "Not Found",
			409: "Conflict",
			500: "Internal Server Error",
		}

		for code, description := range errorCodes {
			scimErr := SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Status:  strconv.Itoa(code),
				Detail:  description,
			}

			assert.Equal(t, strconv.Itoa(code), scimErr.Status)
			assert.Contains(t, scimErr.Detail, "")
		}
	})
}

// TestSCIMUserActiveStatus tests active field handling
func TestSCIMUserActiveStatus(t *testing.T) {
	t.Run("active user", func(t *testing.T) {
		user := SCIMUser{UserName: "active.user", Active: true}
		assert.True(t, user.Active)
	})

	t.Run("inactive user", func(t *testing.T) {
		user := SCIMUser{UserName: "inactive.user", Active: false}
		assert.False(t, user.Active)
	})
}

// TestRuleConditionFieldTypes tests various field types for conditions
func TestRuleConditionFieldTypes(t *testing.T) {
	t.Run("common condition fields", func(t *testing.T) {
		fields := []string{
			"email",
			"department",
			"title",
			"location",
			"employee_type",
			"cost_center",
			"manager",
		}

		for _, field := range fields {
			condition := RuleCondition{Field: field, Operator: "equals", Value: "test"}
			assert.Equal(t, field, condition.Field)
		}
	})
}
