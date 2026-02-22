// Package identity provides example usage of the identity repository
package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRepositoryExamples contains example usage patterns
func TestRepositoryExamples(t *testing.T) {
	t.Run("CreateUser", func(t *testing.T) {
		// Example: Creating a user
		user := NewUser("john.doe")
		user.SetEmail("john@example.com")
		user.SetFirstName("John")
		user.SetLastName("Doe")
		user.Enabled = true
		user.Active = true

		assert.NotEmpty(t, user.ID)
		assert.Equal(t, "john.doe", user.UserName)
		assert.Equal(t, "john@example.com", user.GetEmail())
		assert.Equal(t, "John", user.GetFirstName())
		assert.Equal(t, "Doe", user.GetLastName())
	})

	t.Run("CreateGroup", func(t *testing.T) {
		// Example: Creating a group
		group := NewGroup("Engineering")

		assert.NotEmpty(t, group.ID)
		assert.Equal(t, "Engineering", group.DisplayName)
	})

	t.Run("Pagination", func(t *testing.T) {
		// Example: Setting up pagination
		filter := UserFilter{
			PaginationParams: PaginationParams{
				Limit:  50,
				Offset: 0,
			},
		}

		assert.Equal(t, 50, filter.Limit)
		assert.Equal(t, 0, filter.Offset)
	})
}
