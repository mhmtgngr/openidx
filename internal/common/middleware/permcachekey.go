package middleware

import (
	"strings"
)

// THE PERMISSION CACHE KEY, IN ONE PLACE, BECAUSE TWO PLACES DRIFTED.
//
// PermissionResolver writes the key and identity.invalidatePermissionCache
// deletes it, and until this file existed each built its own idea of what the
// key looked like -- the resolver by joining, the invalidator by guessing with
// a Redis glob. Three things followed, all measured:
//
//   - A ROLE NAME IS NOT A PATTERN. The invalidator interpolated the name into
//     `perms:*<name>*`, and role names arrive in a request body with no
//     validation at all. A role named `ops[x]` made a glob character class, so
//     the SCAN meant to delete that role's entry matched nothing: the revoke
//     returned 200 and the enforcement point kept granting the permission
//     until the entry expired on its own. In a product whose subject is access
//     control, a revoke that reports success and does not take effect is the
//     defect, not the cache.
//
//   - A SUBSTRING IS NOT A ROLE. `perms:*ops*` also deleted `devops`, and
//     since the key carried no tenant term it deleted EVERY tenant's entry for
//     a role of that name. Role names are per-tenant -- the same "admin"
//     exists in every organization -- so one tenant editing a role made every
//     administrator on the install re-query at once.
//
//   - A COMMA IS NOT A SEPARATOR when it can also be a character in a name.
//     The v2 key joined role names with "," so the role set {a, b} and a single
//     role literally named "a,b" produced the SAME key. Two different sets of
//     permissions, one entry, whichever filled it first.
//
// So the key is built here, parsed here, and both callers use these functions.
// The names stay IN the key -- the invalidator has to find entries by role and
// a hash would hide that -- but each one is escaped, so the separator means
// exactly one thing and a name cannot carry structure.

const permCachePrefix = "perms:v3:"

// permEscape makes a role name safe to place between separators. Only two
// characters need it: the escape itself and the separator. Everything else --
// including every Redis glob character -- passes through, because these names
// are no longer used as patterns.
func permEscape(s string) string {
	return strings.NewReplacer("%", "%25", ",", "%2C").Replace(s)
}

func permUnescape(s string) string {
	return strings.NewReplacer("%2C", ",", "%25", "%").Replace(s)
}

// PermissionCacheKey is the entry for one organization and one role set.
// roles must already be sorted; the caller sorts because it also uses the
// sorted slice for the query.
func PermissionCacheKey(orgID string, sortedRoles []string) string {
	escaped := make([]string, len(sortedRoles))
	for i, r := range sortedRoles {
		escaped[i] = permEscape(r)
	}
	return permCachePrefix + permEscape(orgID) + ":" + strings.Join(escaped, ",")
}

// PermissionCacheOrgPattern matches every entry belonging to one organization,
// and nothing else. It is a Redis MATCH pattern, so the org id is escaped for
// glob syntax rather than for the separator -- a different escaping job, which
// is why it is a different function.
func PermissionCacheOrgPattern(orgID string) string {
	return permCachePrefix + globEscape(permEscape(orgID)) + ":*"
}

// PermissionCacheKeyNamesRole reports whether a key is an entry for this
// organization whose role set CONTAINS this role. The comparison is a string
// equality over the decoded names, not a substring or a glob, which is the
// whole point of the file.
func PermissionCacheKeyNamesRole(key, orgID, role string) bool {
	want := permCachePrefix + permEscape(orgID) + ":"
	if !strings.HasPrefix(key, want) {
		return false
	}
	for _, part := range strings.Split(key[len(want):], ",") {
		if permUnescape(part) == role {
			return true
		}
	}
	return false
}

// globEscape neutralises Redis MATCH syntax in a literal. Redis's matcher
// treats a backslash as escaping the next character, so this is its own
// inverse at the server.
func globEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '*', '?', '[', ']', '\\', '^':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
