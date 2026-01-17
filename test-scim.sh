#!/bin/bash
# SCIM 2.0 API Test Script for OpenIDX
# This script demonstrates how to test SCIM endpoints

BASE_URL="http://localhost:8003"
SCIM_BASE="$BASE_URL/scim/v2"

echo "🔍 Testing OpenIDX SCIM 2.0 API"
echo "================================"
echo ""

# Test Service Provider Config
echo "1️⃣  Testing Service Provider Config..."
curl -s -X GET "$SCIM_BASE/ServiceProviderConfig" \
  -H "Content-Type: application/scim+json" | jq '.'
echo ""

# Test Resource Types
echo "2️⃣  Testing Resource Types..."
curl -s -X GET "$SCIM_BASE/ResourceTypes" \
  -H "Content-Type: application/scim+json" | jq '.'
echo ""

# Create a SCIM User
echo "3️⃣  Creating SCIM User..."
USER_RESPONSE=$(curl -s -X POST "$SCIM_BASE/Users" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "scim.user@example.com",
    "name": {
      "givenName": "SCIM",
      "familyName": "User"
    },
    "displayName": "SCIM User",
    "emails": [
      {
        "value": "scim.user@example.com",
        "type": "work",
        "primary": true
      }
    ],
    "active": true
  }')

echo "$USER_RESPONSE" | jq '.'
USER_ID=$(echo "$USER_RESPONSE" | jq -r '.id')
echo "Created user with ID: $USER_ID"
echo ""

# List SCIM Users
echo "4️⃣  Listing SCIM Users..."
curl -s -X GET "$SCIM_BASE/Users?startIndex=1&count=10" \
  -H "Content-Type: application/scim+json" | jq '.'
echo ""

# Get SCIM User by ID
echo "5️⃣  Getting SCIM User by ID..."
curl -s -X GET "$SCIM_BASE/Users/$USER_ID" \
  -H "Content-Type: application/scim+json" | jq '.'
echo ""

# Update SCIM User (Replace)
echo "6️⃣  Updating SCIM User (PUT)..."
curl -s -X PUT "$SCIM_BASE/Users/$USER_ID" \
  -H "Content-Type: application/scim+json" \
  -d "{
    \"schemas\": [\"urn:ietf:params:scim:schemas:core:2.0:User\"],
    \"id\": \"$USER_ID\",
    \"userName\": \"scim.user@example.com\",
    \"name\": {
      \"givenName\": \"SCIM\",
      \"familyName\": \"Updated User\"
    },
    \"displayName\": \"SCIM Updated User\",
    \"emails\": [
      {
        \"value\": \"scim.user@example.com\",
        \"type\": \"work\",
        \"primary\": true
      }
    ],
    \"active\": true
  }" | jq '.'
echo ""

# Patch SCIM User
echo "7️⃣  Patching SCIM User (PATCH)..."
curl -s -X PATCH "$SCIM_BASE/Users/$USER_ID" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "replace",
        "path": "active",
        "value": false
      }
    ]
  }' | jq '.'
echo ""

# Create a SCIM Group
echo "8️⃣  Creating SCIM Group..."
GROUP_RESPONSE=$(curl -s -X POST "$SCIM_BASE/Groups" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "SCIM Test Group",
    "members": []
  }')

echo "$GROUP_RESPONSE" | jq '.'
GROUP_ID=$(echo "$GROUP_RESPONSE" | jq -r '.id')
echo "Created group with ID: $GROUP_ID"
echo ""

# List SCIM Groups
echo "9️⃣  Listing SCIM Groups..."
curl -s -X GET "$SCIM_BASE/Groups?startIndex=1&count=10" \
  -H "Content-Type: application/scim+json" | jq '.'
echo ""

# Add member to group (PATCH)
echo "🔟 Adding user to group (PATCH)..."
curl -s -X PATCH "$SCIM_BASE/Groups/$GROUP_ID" \
  -H "Content-Type: application/scim+json" \
  -d "{
    \"schemas\": [\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],
    \"Operations\": [
      {
        \"op\": \"add\",
        \"path\": \"members\",
        \"value\": [
          {
            \"value\": \"$USER_ID\",
            \"type\": \"User\"
          }
        ]
      }
    ]
  }" | jq '.'
echo ""

# Get Group with members
echo "1️⃣1️⃣  Getting group with members..."
curl -s -X GET "$SCIM_BASE/Groups/$GROUP_ID" \
  -H "Content-Type: application/scim+json" | jq '.'
echo ""

# Delete SCIM User
echo "1️⃣2️⃣  Deleting SCIM User..."
curl -s -X DELETE "$SCIM_BASE/Users/$USER_ID" \
  -H "Content-Type: application/scim+json"
echo "User deleted (HTTP 204 expected)"
echo ""

# Delete SCIM Group
echo "1️⃣3️⃣  Deleting SCIM Group..."
curl -s -X DELETE "$SCIM_BASE/Groups/$GROUP_ID" \
  -H "Content-Type: application/scim+json"
echo "Group deleted (HTTP 204 expected)"
echo ""

echo "✅ SCIM 2.0 API Testing Complete!"
echo ""
echo "📚 SCIM 2.0 Endpoints Available:"
echo "  - GET    /scim/v2/ServiceProviderConfig"
echo "  - GET    /scim/v2/ResourceTypes"
echo "  - GET    /scim/v2/Schemas"
echo "  - GET    /scim/v2/Users"
echo "  - POST   /scim/v2/Users"
echo "  - GET    /scim/v2/Users/:id"
echo "  - PUT    /scim/v2/Users/:id"
echo "  - PATCH  /scim/v2/Users/:id"
echo "  - DELETE /scim/v2/Users/:id"
echo "  - GET    /scim/v2/Groups"
echo "  - POST   /scim/v2/Groups"
echo "  - GET    /scim/v2/Groups/:id"
echo "  - PUT    /scim/v2/Groups/:id"
echo "  - PATCH  /scim/v2/Groups/:id"
echo "  - DELETE /scim/v2/Groups/:id"
