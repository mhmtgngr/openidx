#!/usr/bin/env bash
# Self-test for check-test-reachability.sh.
#
# The last two cases are the ones that matter: they take the two suites that
# were actually dark -- internal/oauth's SAML tenant-isolation tests and the
# v172 migration test -- and put each back into the shape it was merged in. A
# guard for a defect that has already happened once should be shown failing on
# that exact defect, not on a fixture invented to be easy.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-test-reachability.sh"

pass=0; fail=0
expect() { # expect <ok|red> <name> ; tree already staged in $WD
  local want="$1" name="$2" out rc
  out="$(OPENIDX_TESTREACH_ROOT="$WD" bash "$GUARD" 2>&1)"; rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = red ] && [ $rc -ne 0 ]; }; then
    echo "  ok   $name"; pass=$((pass+1))
  else
    echo "  FAIL $name (rc=$rc, wanted $want)"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fresh() { WD="$TMP/wd"; rm -rf "$WD"; mkdir -p "$WD/pkg"; }

# The tree as it stands must pass, or every red case below proves nothing.
WD="$ROOT"
expect ok "the repository's own test helpers are all reachable from CI"

# --- synthetic shapes -------------------------------------------------------

# 1. The bare defect: gated on the variable, nothing else.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func setupDB(t *testing.T) *pool {
	url := os.Getenv("OPENIDX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("OPENIDX_TEST_DATABASE_URL not set")
	}
	return open(url)
}
GO
expect red "gated on the variable with no other path"

# 2. …with a container fallback.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func setupDB(t *testing.T) *pool {
	if url := os.Getenv("OPENIDX_TEST_DATABASE_URL"); url != "" {
		return open(url)
	}
	c := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, gcr)
	})
	return fromContainer(c)
}
GO
expect ok "container fallback"

# 3. …with the DATABASE_URL ci.yml actually sets.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func setupDB(t *testing.T) *pool {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("OPENIDX_TEST_DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("no database")
	}
	return open(dsn)
}
GO
expect ok "reads the DATABASE_URL ci.yml supplies"

# 4. …delegating to a self-sufficient helper in the same package.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func setupNarrowDB(t *testing.T) *pool {
	if url := os.Getenv("OPENIDX_TEST_DATABASE_URL"); url != "" {
		return open(url)
	}
	return containerDB(t)
}
GO
cat >"$WD/pkg/b_test.go" <<'GO'
package pkg

func containerDB(t *testing.T) *pool {
	c := testsupport.RunOrSkip(t, img, start)
	return fromContainer(c)
}
GO
expect ok "delegates to a container helper in the same package"

# 5. …but a helper in ANOTHER package is not reachable from here.
fresh
mkdir -p "$WD/other"
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func setupNarrowDB(t *testing.T) *pool {
	if url := os.Getenv("OPENIDX_TEST_DATABASE_URL"); url != "" {
		return open(url)
	}
	return containerDB(t)
}
GO
cat >"$WD/other/b_test.go" <<'GO'
package other

func containerDB(t *testing.T) *pool {
	c := testsupport.RunOrSkip(t, img, start)
	return fromContainer(c)
}
GO
expect red "the helper it delegates to is in a different package"

# 6. The prose trap. A comment mentioning testcontainers is not a call to one,
#    and this is the exact wording the dark SAML helper carried.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

// It deliberately does NOT use testcontainers, unlike the other database-backed
// suites in this package.
func setupDB(t *testing.T) *pool {
	url := os.Getenv("OPENIDX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("OPENIDX_TEST_DATABASE_URL not set")
	}
	return open(url)
}
GO
expect red "a comment naming testcontainers is not a fallback"

# 7. The marker, with a reason and without one.
fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func setupDB(t *testing.T) *pool {
	//testreach:ignore needs a Postgres built with a non-default locale, which no container image here provides
	url := os.Getenv("OPENIDX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("no database")
	}
	return open(url)
}
GO
expect ok "//testreach:ignore with a reason"

fresh
cat >"$WD/pkg/a_test.go" <<'GO'
package pkg

func setupDB(t *testing.T) *pool {
	//testreach:ignore
	url := os.Getenv("OPENIDX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("no database")
	}
	return open(url)
}
GO
expect red "a bare //testreach:ignore is itself a finding"

# --- the two suites that were really dark -----------------------------------

# 8. internal/oauth as it stands: the SAML helper falls back to ssfSetupTestDB.
WD="$TMP/oauth"; rm -rf "$WD"; mkdir -p "$WD/oauth"
cp "$ROOT/internal/oauth/saml_sp_tenant_isolation_test.go" "$ROOT/internal/oauth/ssf_test.go" "$WD/oauth/"
expect ok "internal/oauth's SAML isolation suite reaches a database"

# 9. …regressed to the shape it was merged in: the container fallback removed,
#    so the suite skips on every CI run while the job reports success.
python3 - "$WD/oauth/saml_sp_tenant_isolation_test.go" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
assert "ssfSetupTestDB(t)" in s, "fixture drift: the SAML helper no longer delegates"
s = s.replace("db, containerCleanup := ssfSetupTestDB(t)",
              't.Skip("OPENIDX_TEST_DATABASE_URL not set; skipping SAML isolation tests")')
open(p, "w").write(s)
PY
expect red "SAML isolation back to skipping unless the variable is set"

# 10. internal/migrations as it stands: v172 goes through adminPoolOrSkip.
WD="$TMP/mig"; rm -rf "$WD"; mkdir -p "$WD/migrations"
cp "$ROOT/internal/migrations/v172_test.go" "$ROOT/internal/migrations/least_privilege_owner_test.go" "$WD/migrations/"
expect ok "the v172 migration test reaches a database"

# 11. …regressed the same way.
python3 - "$WD/migrations/v172_test.go" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
assert "adminPoolOrSkip(t)" in s, "fixture drift: v172 no longer delegates"
s = s.replace("db, _, cleanup := adminPoolOrSkip(t)",
              'url := os.Getenv("OPENIDX_TEST_DATABASE_URL")\n\tif url == "" {\n\t\tt.Skip("OPENIDX_TEST_DATABASE_URL not set")\n\t}')
open(p, "w").write(s)
PY
expect red "v172 back to skipping unless the variable is set"

echo "check-test-reachability.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
