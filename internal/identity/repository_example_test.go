// Package identity provides example usage of the identity repository
package identity

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/openidx/openidx/internal/common/database"
)

// ExampleRepositoryUsage demonstrates how to use the identity repository
func ExampleRepositoryUsage() {
	// This is example code - do not run in production without proper config

	// 1. Create database connection
	db, err := database.NewPostgres("postgres://localhost:5432/openidx?sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// 2. Create repository
	repo := NewPostgreSQLRepository(db.Pool, "http://localhost:8001/scim/v2")
	ctx := context.Background()

	// 3. Create an organization
	org := NewOrganization("acme-corp", "Acme Corporation")
	org.Domain = strPtr("acme.com")
	org.Description = strPtr("Acme Corporation - Leading provider of everything")
	org.Active = true

	err = repo.CreateOrganization(ctx, org)
	if err != nil {
		log.Fatalf("Failed to create organization: %v", err)
	}
	fmt.Printf("Created organization: %s (%s)\n", org.Name, org.ID)

	// 4. Create a user with SCIM-compatible fields
	user := NewUser("john.doe")
	user.DisplayName = strPtr("John Doe")
	user.Name = &Name{
		GivenName:  strPtr("John"),
		FamilyName: strPtr("Doe"),
	}
	user.GetEmail()s = []Email{
		{
			Value:   "john.doe@acme.com",
			Type:    strPtr("work"),
			Primary: boolPtr(true),
		},
	}
	user.PhoneNumbers = []PhoneNumber{
		{
			Value:   "+1-555-0123",
			Type:    strPtr("work"),
			Primary: boolPtr(true),
		},
	}
	user.Active = true
	user.Enabled = true
	user.GetEmail()Verified = true
	user.OrganizationID = &org.ID
	user.Source = strPtr("manual")

	err = repo.CreateUser(ctx, user)
	if err != nil {
		log.Fatalf("Failed to create user: %v", err)
	}
	fmt.Printf("Created user: %s (%s)\n", user.UserName, user.ID)

	// 5. Create a group
	group := NewGroup("Engineering")
	group.DisplayName = "Engineering Team"
	group.OrganizationID = &org.ID

	err = repo.CreateGroup(ctx, group)
	if err != nil {
		log.Fatalf("Failed to create group: %v", err)
	}
	fmt.Printf("Created group: %s (%s)\n", group.DisplayName, group.ID)

	// 6. Add user to group
	err = repo.AddGroupMember(ctx, group.ID, user.ID)
	if err != nil {
		log.Fatalf("Failed to add user to group: %v", err)
	}
	fmt.Printf("Added user %s to group %s\n", user.UserName, group.DisplayName)

	// 7. Query user by username
	foundUser, err := repo.GetUserByUsername(ctx, "john.doe")
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}
	fmt.Printf("Found user: %s - Primary Email: %s\n",
		foundUser.GetFormattedName(),
		foundUser.GetPrimaryEmail())

	// 8. List users with filter
	filter := UserFilter{
		PaginationParams: PaginationParams{
			Limit:     10,
			Offset:    0,
			SortBy:    "username",
			SortOrder: "asc",
		},
		Query:          strPtr("john"),
		OrganizationID: &org.ID,
	}

	listResult, err := repo.ListUsers(ctx, filter)
	if err != nil {
		log.Fatalf("Failed to list users: %v", err)
	}
	fmt.Printf("Listed %d users (total: %d)\n",
		len(listResult.Resources.([]*User)),
		listResult.TotalResults)

	// 9. Update user
	foundUser.DisplayName = strPtr("John Doe II")
	foundUser.UpdatedAt = time.Now()
	err = repo.UpdateUser(ctx, foundUser)
	if err != nil {
		log.Fatalf("Failed to update user: %v", err)
	}
	fmt.Printf("Updated user: %s\n", foundUser.UserName)

	// 10. List groups for user
	groupFilter := GroupFilter{
		PaginationParams: PaginationParams{
			Limit:  10,
			Offset: 0,
		},
	}
	groupsResult, err := repo.ListGroupsByUser(ctx, user.ID, groupFilter)
	if err != nil {
		log.Fatalf("Failed to list user groups: %v", err)
	}
	fmt.Printf("User belongs to %d groups\n",
		len(groupsResult.Resources.([]*Group)))

	// 11. List all organizations
	orgFilter := OrganizationFilter{
		PaginationParams: PaginationParams{
			Limit:  10,
			Offset: 0,
		},
	}
	orgsResult, err := repo.ListOrganizations(ctx, orgFilter)
	if err != nil {
		log.Fatalf("Failed to list organizations: %v", err)
	}
	fmt.Printf("Total organizations: %d\n", orgsResult.TotalResults)

	// 12. Soft delete user (sets deleted_at timestamp)
	err = repo.DeleteUser(ctx, user.ID)
	if err != nil {
		log.Fatalf("Failed to delete user: %v", err)
	}
	fmt.Printf("Deleted user: %s\n", user.ID)
}

// ExampleSCIMIntegration shows SCIM 2.0 integration patterns
func ExampleSCIMIntegration() {
	db, _ := database.NewPostgres("postgres://localhost:5432/openidx?sslmode=disable")
	defer db.Close()

	repo := NewPostgreSQLRepository(db.Pool, "http://localhost:8001/scim/v2")
	ctx := context.Background()

	// SCIM provisioning: Create user from external system
	externalUserID := "ext-12345-from-azure-ad"

	// Check if user already exists by external ID
	existingUser, err := repo.GetUserByExternalID(ctx, externalUserID)
	if err != nil {
		// User doesn't exist, create new
		user := NewUser("jane.smith")
		user.ExternalID = &externalUserID
		user.DisplayName = strPtr("Jane Smith")
		user.GetEmail()s = []Email{
			{
				Value:   "jane.smith@example.com",
				Type:    strPtr("work"),
				Primary: boolPtr(true),
			},
		}
		user.Active = true
		user.Source = strPtr("scim") // Mark as from SCIM sync

		user.UpdateMeta(repo.baseURL)

		err = repo.CreateUser(ctx, user)
		if err != nil {
			log.Printf("Failed to create SCIM user: %v", err)
			return
		}
		fmt.Printf("Provisioned SCIM user: %s\n", user.ID)
	} else {
		// User exists, update (SCIM sync)
		existingUser.DisplayName = strPtr("Jane Smith Updated")
		existingUser.UpdateMeta(repo.baseURL)

		err = repo.UpdateUser(ctx, existingUser)
		if err != nil {
			log.Printf("Failed to update SCIM user: %v", err)
			return
		}
		fmt.Printf("Updated SCIM user: %s\n", existingUser.ID)
	}
}

// ExamplePagination shows pagination patterns
func ExamplePagination() {
	db, _ := database.NewPostgres("postgres://localhost:5432/openidx?sslmode=disable")
	defer db.Close()

	repo := NewPostgreSQLRepository(db.Pool, "http://localhost:8001/scim/v2")
	ctx := context.Background()

	// First page
	pageSize := 50
	page := 0

	filter := UserFilter{
		PaginationParams: PaginationParams{
			Limit:     pageSize,
			Offset:    page * pageSize,
			SortBy:    "created_at",
			SortOrder: "desc",
		},
		Active: boolPtr(true),
	}

	result, err := repo.ListUsers(ctx, filter)
	if err != nil {
		log.Printf("Failed to list users: %v", err)
		return
	}

	users := result.Resources.([]*User)
	fmt.Printf("Page %d: showing %d of %d total users\n",
		page+1, len(users), result.TotalResults)

	// Calculate pagination metadata
	totalPages := (result.TotalResults + pageSize - 1) / pageSize
	hasNext := page < totalPages-1
	hasPrev := page > 0

	fmt.Printf("Pagination: %d/%d pages (next: %v, prev: %v)\n",
		page+1, totalPages, hasNext, hasPrev)
}

// Helper functions
func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}
