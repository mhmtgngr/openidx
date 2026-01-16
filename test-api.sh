#!/bin/bash

# OpenIDX API Test Script
# This script tests the basic API endpoints to verify the system is working

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="${API_URL:-http://localhost:8001}"
IDENTITY_API="$BASE_URL/api/v1/identity"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
print_header() {
    echo -e "\n${YELLOW}========================================${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((TESTS_PASSED++))
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    ((TESTS_FAILED++))
}

test_endpoint() {
    local method=$1
    local url=$2
    local data=$3
    local expected_status=$4
    local description=$5

    echo -e "\nTesting: $description"
    echo "  $method $url"

    if [ -z "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
            -H "Content-Type: application/json" \
            -d "$data")
    fi

    # Extract status code (last line) and body (everything else)
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$status_code" = "$expected_status" ]; then
        print_success "Status: $status_code (expected $expected_status)"
        if [ -n "$body" ] && [ "$body" != "null" ]; then
            echo "  Response: $body" | head -c 200
            echo "..."
        fi
    else
        print_error "Status: $status_code (expected $expected_status)"
        echo "  Response: $body"
        return 1
    fi
}

# Main test suite
main() {
    print_header "OpenIDX API Test Suite"

    echo "Testing API at: $BASE_URL"
    echo "Date: $(date)"

    # Test 1: Health Check
    print_header "1. Health Checks"

    test_endpoint "GET" "$BASE_URL/health" "" "200" "Service health check"
    test_endpoint "GET" "$BASE_URL/ready" "" "200" "Service readiness check"

    # Test 2: User Management
    print_header "2. User Management"

    # Create user
    USER_DATA='{
        "id": "test-user-001",
        "username": "test.user",
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User",
        "enabled": true,
        "email_verified": true
    }'

    test_endpoint "POST" "$IDENTITY_API/users" "$USER_DATA" "201" "Create user"

    # Get user
    test_endpoint "GET" "$IDENTITY_API/users/test-user-001" "" "200" "Get user by ID"

    # List users
    test_endpoint "GET" "$IDENTITY_API/users" "" "200" "List all users"

    # Update user
    UPDATE_DATA='{
        "username": "test.user",
        "email": "updated@example.com",
        "first_name": "Test",
        "last_name": "Updated",
        "enabled": true,
        "email_verified": true
    }'

    test_endpoint "PUT" "$IDENTITY_API/users/test-user-001" "$UPDATE_DATA" "200" "Update user"

    # Test 3: Group Management
    print_header "3. Group Management"

    test_endpoint "GET" "$IDENTITY_API/groups" "" "200" "List all groups"

    # Test 4: Session Management
    print_header "4. Session Management"

    test_endpoint "GET" "$IDENTITY_API/users/test-user-001/sessions" "" "200" "Get user sessions"

    # Test 5: Cleanup
    print_header "5. Cleanup"

    test_endpoint "DELETE" "$IDENTITY_API/users/test-user-001" "" "204" "Delete test user"

    # Test 6: Error Handling
    print_header "6. Error Handling"

    test_endpoint "GET" "$IDENTITY_API/users/nonexistent" "" "404" "Get non-existent user"

    # Summary
    print_header "Test Summary"

    TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))
    echo "Total Tests: $TOTAL_TESTS"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed! ✓${NC}\n"
        exit 0
    else
        echo -e "\n${RED}Some tests failed! ✗${NC}\n"
        exit 1
    fi
}

# Check if services are running
check_services() {
    echo "Checking if services are running..."

    if ! curl -s "$BASE_URL/health" > /dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to $BASE_URL${NC}"
        echo "Please ensure services are running:"
        echo "  docker-compose -f deployments/docker/docker-compose.yml up -d"
        exit 1
    fi

    echo -e "${GREEN}Services are running!${NC}\n"
}

# Run tests
check_services
main
