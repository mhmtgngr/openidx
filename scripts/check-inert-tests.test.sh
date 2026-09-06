#!/usr/bin/env bash
# Self-test for check-inert-tests.sh.
#
# Cases 1 and 2 are verbatim the two shapes that were in the tree: the subtest
# form from internal/governance/request_test.go and the whole-function form from
# internal/common/cache/response_test.go. Cases 3 to 5 are the skips that are
# legitimate, and a guard that reddened on those would be turned off within a
# week.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-inert-tests.sh"

pass=0; fail=0
expect() { # expect <ok|red> <name>; tree staged in $WD
  local want="$1" name="$2" out rc
  out="$(OPENIDX_INERT_ROOT="$WD" bash "$GUARD" 2>&1)"; rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = red ] && [ $rc -ne 0 ]; }; then
    echo "  ok   $name"; pass=$((pass+1))
  else
    echo "  FAIL $name (rc=$rc, wanted $want)"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fresh() { WD="$TMP/wd"; rm -rf "$WD"; mkdir -p "$WD/pkg"; }

# The repository must pass, or every red case below proves nothing.
WD="$ROOT"
expect ok "the repository has no inert tests left"

# 1. The subtest shape, as it stood in internal/governance/request_test.go.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func TestSubmitRequest(t *testing.T) {
	t.Run("request with empty approval chain fails", func(t *testing.T) {
		t.Skip("DB mock not available - requires integration test")
	})
}
GO
expect red "a subtest whose body is one unconditional skip"

# 2. The whole-function shape, as it stood in internal/common/cache.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func TestResponseCache_GetStats(t *testing.T) {
	t.Skip("Requires real Redis client")
}
GO
expect red "a test function whose body is one unconditional skip"

# 3. A skip behind a condition is the legitimate use: a decision about the
#    environment, made at run time.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func TestNeedsADatabase(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	defer cleanup()
	assertThings(t, db)
}
GO
expect ok "a skip guarded by a condition"

# 4. …including one that skips first and then does real work.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func TestShortMode(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	doTheSlowThing(t)
}
GO
expect ok "testing.Short() with a body after it"

# 5. A subtest that skips conditionally and then asserts.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func TestPlatform(t *testing.T) {
	t.Run("unix only", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("not on windows")
		}
		checkUnixThing(t)
	})
}
GO
expect ok "a conditional skip inside a subtest"

# 6. A tree with no tests at all is a finding: a guard that greens on an empty
#    scan is how a check ends up wired to the wrong directory and nobody knows.
WD="$TMP/empty"; rm -rf "$WD"; mkdir -p "$WD"
expect red "no test files found at all"

echo "check-inert-tests.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
