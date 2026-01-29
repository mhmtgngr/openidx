package provisioning

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
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
