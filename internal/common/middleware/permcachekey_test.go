package middleware

import (
	"strings"
	"testing"
)

// THE TWO HALVES OF THE PERMISSION CACHE HAVE TO AGREE, and these are the
// properties they agree on. PermissionResolver writes a key and
// identity.invalidatePermissionCache finds it again; when those were separate
// implementations, one joined with a comma and the other guessed with a Redis
// glob, and three defects followed.

// A role name is arbitrary text -- handleCreateRole binds it from the request
// body with no validation -- so the separator has to survive a name that
// contains it. Otherwise the role SET {reader, writer} and a single role NAMED
// "reader,writer" are the same entry.
func TestARoleNamedLikeARoleSetIsADifferentKey(t *testing.T) {
	set := PermissionCacheKey("org1", []string{"reader", "writer"})
	one := PermissionCacheKey("org1", []string{"reader,writer"})
	if set == one {
		t.Fatalf("the set {reader, writer} and the role named %q share the key %q", "reader,writer", set)
	}

	// And each still recognises its own members, which is what invalidation
	// walks the keyspace to decide.
	for _, r := range []string{"reader", "writer"} {
		if !PermissionCacheKeyNamesRole(set, "org1", r) {
			t.Errorf("the set key does not name %q", r)
		}
	}
	if !PermissionCacheKeyNamesRole(one, "org1", "reader,writer") {
		t.Errorf("the single-role key does not name its own role")
	}
	if PermissionCacheKeyNamesRole(one, "org1", "reader") {
		t.Errorf("a role named %q was read as containing the role %q", "reader,writer", "reader")
	}
	if PermissionCacheKeyNamesRole(set, "org1", "reader,writer") {
		t.Errorf("the set {reader, writer} was read as the role named %q", "reader,writer")
	}
}

// The escape must survive its own escape character, or two different names
// collide one level down.
func TestNamesThatCollideOnlyAfterEscapingStayDistinct(t *testing.T) {
	for _, pair := range [][2]string{
		{"a%2Cb", "a,b"}, // the literal text of the escape versus what it encodes
		{"a%25b", "a%b"}, // and the escape of the escape
		{"%2C", ","},     //
	} {
		x := PermissionCacheKey("org1", []string{pair[0]})
		y := PermissionCacheKey("org1", []string{pair[1]})
		if x == y {
			t.Errorf("roles %q and %q share the key %q", pair[0], pair[1], x)
		}
		if !PermissionCacheKeyNamesRole(x, "org1", pair[0]) || PermissionCacheKeyNamesRole(x, "org1", pair[1]) {
			t.Errorf("key for %q does not distinguish it from %q", pair[0], pair[1])
		}
	}
}

// One tenant's entries only. Role names are per-tenant -- the same "admin"
// exists in every organization -- so a pattern with no tenant term makes one
// tenant's role edit empty every other tenant's cache.
func TestTheOrgPatternDoesNotReachAnotherOrg(t *testing.T) {
	key := PermissionCacheKey("org2", []string{"admin"})
	if PermissionCacheKeyNamesRole(key, "org1", "admin") {
		t.Errorf("org1's invalidation claimed org2's key %q", key)
	}
	if !PermissionCacheKeyNamesRole(key, "org2", "admin") {
		t.Errorf("org2's invalidation did not claim its own key %q", key)
	}
}

// THE PATTERN IS A PATTERN, so whatever goes into it is escaped for glob
// syntax. Today every org id is a UUID and none of this is reachable; the
// escape is here so that an id which is not a UUID cannot silently turn the
// invalidation into a scan that matches nothing -- which is exactly how the
// role name broke the previous version.
func TestTheOrgPatternNeutralisesGlobSyntax(t *testing.T) {
	for _, org := range []string{"org[1]", "org*", "org?", `org\1`, "org^"} {
		pattern := PermissionCacheOrgPattern(org)
		for _, meta := range []string{"[", "]", "*", "?", "^", `\`} {
			if !strings.Contains(org, meta) {
				continue
			}
			if !strings.Contains(pattern, `\`+meta) {
				t.Errorf("org %q: pattern %q leaves %q unescaped, so Redis reads it as syntax", org, pattern, meta)
			}
		}
		// The trailing wildcard is the only glob the pattern is allowed to mean.
		if !strings.HasSuffix(pattern, ":*") {
			t.Errorf("org %q: pattern %q lost its trailing wildcard", org, pattern)
		}
	}
}
