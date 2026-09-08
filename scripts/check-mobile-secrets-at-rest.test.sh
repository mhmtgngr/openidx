#!/usr/bin/env bash
# Self-test for check-mobile-secrets-at-rest.sh.
#
# The first case is the tree's own shape before the fix: a hand-written,
# deliberately-committed manifest with no allowBackup attribute, which is the
# platform default TRUE. It is the case that matters most, because it is the one
# that shipped.
#
# The negatives matter as much. A guard that reddens on a manifest which is
# already correct is one somebody switches off, and a guard that greens on a
# rules file with an <include> in it — the file that reads like a control and
# is not — would be this repository's own defect class in the tool built to
# catch it.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-mobile-secrets-at-rest.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

RULES_OK='<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="root" />
        <exclude domain="file" />
        <exclude domain="database" />
        <exclude domain="sharedpref" />
        <exclude domain="external" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="root" />
        <exclude domain="file" />
        <exclude domain="database" />
        <exclude domain="sharedpref" />
        <exclude domain="external" />
    </device-transfer>
</data-extraction-rules>'

SWIFT_OK='public class OpenidxEnginePlugin: NSObject {
  private func dispatch(_ method: String, _ args: [String: Any]?) throws -> Any? {
    switch method {
    case "start":
      let configDir = str(args, "configDir")
      try excludeFromBackup(configDir)
      try callVoid { MobileStart(configDir, $0) }
      return nil
    case "status":
      return try callString { MobileStatus($0) }
    default:
      return nil
    }
  }
  private func excludeFromBackup(_ path: String) throws {
    var url = URL(fileURLWithPath: path)
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try url.setResourceValues(values)
  }
}'

# run_case <name> <want-exit> <manifest-application-attrs> <rules-xml-or-NONE> <swift>
run_case() {
    local name="$1" want="$2" attrs="$3" rules="$4" swift="$5"
    local dir="$TMP/case"
    rm -rf "$dir"
    mkdir -p "$dir/res/xml"

    printf '%s\n' '<manifest xmlns:android="http://schemas.android.com/apk/res/android">' \
        "    <application android:label=\"OpenIDX\" $attrs>" \
        '        <activity android:name=".MainActivity" />' \
        '    </application>' \
        '</manifest>' > "$dir/AndroidManifest.xml"

    [ "$rules" != "NONE" ] && printf '%s\n' "$rules" > "$dir/res/xml/data_extraction_rules.xml"
    printf '%s\n' "$swift" > "$dir/Plugin.swift"

    local out rc
    out=$(cd "$ROOT" && CHECK_MOBILE_SECRETS_MANIFESTS="$dir/AndroidManifest.xml" \
        CHECK_MOBILE_SECRETS_SWIFT="$dir/Plugin.swift" bash "$GUARD" --enforce 2>&1)
    rc=$?
    if [ "$rc" -eq "$want" ]; then
        echo "  ok   $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL $name (exit $rc, want $want)"
        echo "$out" | sed 's/^/       /'
        FAIL=$((FAIL + 1))
    fi
}

OK_ATTRS='android:allowBackup="false" android:dataExtractionRules="@xml/data_extraction_rules"'

echo "check-mobile-secrets-at-rest self-test"

run_case "a correct manifest and plugin pass" 0 \
    "$OK_ATTRS" "$RULES_OK" "$SWIFT_OK"

# --- Android: the attribute that is protection by absence of a default -------

run_case "no allowBackup attribute at all is a finding (the shipped state)" 1 \
    'android:dataExtractionRules="@xml/data_extraction_rules"' "$RULES_OK" "$SWIFT_OK"

run_case 'allowBackup="true" is a finding' 1 \
    'android:allowBackup="true" android:dataExtractionRules="@xml/data_extraction_rules"' \
    "$RULES_OK" "$SWIFT_OK"

run_case "allowBackup alone, without dataExtractionRules, still transfers D2D" 1 \
    'android:allowBackup="false"' "NONE" "$SWIFT_OK"

run_case "dataExtractionRules pointing at a resource that does not exist" 1 \
    "$OK_ATTRS" "NONE" "$SWIFT_OK"

run_case "dataExtractionRules that is not an @xml/ reference" 1 \
    'android:allowBackup="false" android:dataExtractionRules="false"' "$RULES_OK" "$SWIFT_OK"

# --- Android: a rules file that reads as a control and is not ---------------

run_case "a rules file with no device-transfer section" 1 "$OK_ATTRS" \
'<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="root" />
        <exclude domain="file" />
        <exclude domain="database" />
        <exclude domain="sharedpref" />
        <exclude domain="external" />
    </cloud-backup>
</data-extraction-rules>' "$SWIFT_OK"

run_case "a rules file that includes a domain" 1 "$OK_ATTRS" \
'<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <include domain="sharedpref" />
        <exclude domain="root" />
        <exclude domain="file" />
        <exclude domain="database" />
        <exclude domain="sharedpref" />
        <exclude domain="external" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="root" />
        <exclude domain="file" />
        <exclude domain="database" />
        <exclude domain="sharedpref" />
        <exclude domain="external" />
    </device-transfer>
</data-extraction-rules>' "$SWIFT_OK"

run_case "a rules file that misses one domain" 1 "$OK_ATTRS" \
'<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="root" />
        <exclude domain="file" />
        <exclude domain="database" />
        <exclude domain="sharedpref" />
        <exclude domain="external" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="root" />
        <exclude domain="file" />
        <exclude domain="database" />
        <exclude domain="external" />
    </device-transfer>
</data-extraction-rules>' "$SWIFT_OK"

# --- iOS: order is the rule, not presence -----------------------------------

run_case "the iOS exclusion after MobileStart is a finding" 1 "$OK_ATTRS" "$RULES_OK" \
'public class OpenidxEnginePlugin: NSObject {
  private func dispatch(_ method: String, _ args: [String: Any]?) throws -> Any? {
    switch method {
    case "start":
      let configDir = str(args, "configDir")
      try callVoid { MobileStart(configDir, $0) }
      try excludeFromBackup(configDir)
      return nil
    default:
      return nil
    }
  }
  private func excludeFromBackup(_ path: String) throws {
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
  }
}'

run_case "the helper defined but never called from start — what a grep would pass" 1 \
    "$OK_ATTRS" "$RULES_OK" \
'public class OpenidxEnginePlugin: NSObject {
  private func dispatch(_ method: String, _ args: [String: Any]?) throws -> Any? {
    switch method {
    case "start":
      try callVoid { MobileStart(str(args, "configDir"), $0) }
      return nil
    default:
      return nil
    }
  }
  private func excludeFromBackup(_ path: String) throws {
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
  }
}'

run_case "a helper that never sets isExcludedFromBackup excludes nothing" 1 \
    "$OK_ATTRS" "$RULES_OK" \
'public class OpenidxEnginePlugin: NSObject {
  private func dispatch(_ method: String, _ args: [String: Any]?) throws -> Any? {
    switch method {
    case "start":
      let configDir = str(args, "configDir")
      try excludeFromBackup(configDir)
      try callVoid { MobileStart(configDir, $0) }
      return nil
    default:
      return nil
    }
  }
  private func excludeFromBackup(_ path: String) throws {
    NSLog("would exclude %@", path)
  }
}'

run_case "a plugin with no start case at all is a finding, not a silent pass" 1 \
    "$OK_ATTRS" "$RULES_OK" \
'public class OpenidxEnginePlugin: NSObject {
  private func dispatch(_ method: String, _ args: [String: Any]?) throws -> Any? {
    switch method {
    case "status":
      return try callString { MobileStatus($0) }
    default:
      return nil
    }
  }
}'

# The exclusion must be read from the start case specifically: a call in a
# neighbouring case is not the one that matters.
run_case "the call in a different case does not count" 1 "$OK_ATTRS" "$RULES_OK" \
'public class OpenidxEnginePlugin: NSObject {
  private func dispatch(_ method: String, _ args: [String: Any]?) throws -> Any? {
    switch method {
    case "start":
      try callVoid { MobileStart(str(args, "configDir"), $0) }
      return nil
    case "enroll":
      try excludeFromBackup(str(args, "configDir"))
      return try callString { MobileEnroll(str(args, "code"), $0) }
    default:
      return nil
    }
  }
  private func excludeFromBackup(_ path: String) throws {
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
  }
}'

echo
echo "check-mobile-secrets-at-rest self-test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
