#!/usr/bin/env bash
# Self-test for ci-configure-ios-deeplinks.sh.
#
# The negatives carry the weight, as ever. A configure step that silently
# succeeds on a missing file is worse than no step at all: it prints a
# reassuring line into the log and the scheme still is not registered, which is
# exactly the shape this script exists to end.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/ci-configure-ios-deeplinks.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

ok() { echo "  ok   $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL $1"; shift; [ $# -gt 0 ] && echo "$*" | sed 's/^/       /'; FAIL=$((FAIL + 1)); }

# A minimal but realistic generated Info.plist: the keys `flutter create` puts
# there, and no CFBundleURLTypes -- which is the state this script fixes.
fresh_plist() {
    cat > "$1" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>$(DEVELOPMENT_LANGUAGE)</string>
	<key>CFBundleDisplayName</key>
	<string>Openidx Client</string>
	<key>CFBundleIdentifier</key>
	<string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
	<key>UISupportedInterfaceOrientations</key>
	<array>
		<string>UIInterfaceOrientationPortrait</string>
	</array>
</dict>
</plist>
EOF
}

scheme_count() {
    python3 - "$1" <<'PYEOF'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    p = plistlib.load(f)
n = 0
for entry in p.get("CFBundleURLTypes", []):
    n += entry.get("CFBundleURLSchemes", []).count("openidx")
print(n)
PYEOF
}

# --- the thing it is for -----------------------------------------------------
P="$TMP/Info.plist"
fresh_plist "$P"
if out=$(bash "$SCRIPT" "$P" 2>&1) && [ "$(scheme_count "$P")" = "1" ]; then
    ok "a generated Info.plist gains the openidx scheme"
else
    bad "a generated Info.plist gains the openidx scheme" "$out"
fi

# The scheme is read from the Android manifest, so it must be the one Android
# actually routes -- not a constant repeated here.
if grep -q 'android:scheme="openidx"' "$ROOT/client/android/app/src/main/AndroidManifest.xml"; then
    ok "the scheme it wrote is the one the Android manifest declares"
else
    bad "the scheme it wrote is the one the Android manifest declares" \
        "AndroidManifest.xml no longer declares android:scheme=\"openidx\""
fi

# --- idempotence: CI runs this on every job ----------------------------------
if out=$(bash "$SCRIPT" "$P" 2>&1) && [ "$(scheme_count "$P")" = "1" ]; then
    ok "running it twice does not register the scheme twice"
else
    bad "running it twice does not register the scheme twice" "$out (count=$(scheme_count "$P"))"
fi

# --- it must not eat the rest of the file ------------------------------------
if python3 - "$P" <<'PYEOF'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    p = plistlib.load(f)
need = ["CFBundleDevelopmentRegion", "CFBundleDisplayName", "CFBundleIdentifier",
        "UISupportedInterfaceOrientations"]
missing = [k for k in need if k not in p]
sys.exit(1 if missing else 0)
PYEOF
then
    ok "every key Flutter generated survives the patch"
else
    bad "every key Flutter generated survives the patch"
fi

# --- the negatives -----------------------------------------------------------
# A missing plist means the caller ran this before `flutter create`, or on a job
# that never materialized iOS. Silently succeeding there is the whole defect.
if bash "$SCRIPT" "$TMP/nope/Info.plist" >/dev/null 2>&1; then
    bad "a missing Info.plist is an error, not a no-op"
else
    ok "a missing Info.plist is an error, not a no-op"
fi

# An existing, unrelated CFBundleURLTypes entry must be kept, not replaced.
P2="$TMP/Info2.plist"
fresh_plist "$P2"
python3 - "$P2" <<'PYEOF'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    p = plistlib.load(f)
p["CFBundleURLTypes"] = [{"CFBundleURLSchemes": ["fbauth2"]}]
with open(sys.argv[1], "wb") as f:
    plistlib.dump(p, f)
PYEOF
bash "$SCRIPT" "$P2" >/dev/null 2>&1
if python3 - "$P2" <<'PYEOF'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    p = plistlib.load(f)
schemes = [s for e in p.get("CFBundleURLTypes", []) for s in e.get("CFBundleURLSchemes", [])]
sys.exit(0 if "fbauth2" in schemes and "openidx" in schemes else 1)
PYEOF
then
    ok "an unrelated URL type already in the plist is kept"
else
    bad "an unrelated URL type already in the plist is kept"
fi

echo
echo "ci-configure-ios-deeplinks.test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
