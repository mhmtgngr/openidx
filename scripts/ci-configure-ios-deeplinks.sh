#!/usr/bin/env bash
# Register the app's custom URL scheme in the GENERATED iOS Info.plist, so the
# OAuth redirect can reach the app.
#
# WHY THIS EXISTS. Two openidx:// links arrive from OUTSIDE the app and must be
# routed by the operating system:
#
#   openidx://oauth-callback?code=…&state=…   the server's 302 after login
#                                             (agent/internal/sso/sso.go's
#                                             MobileRedirectURI)
#   openidx://enroll?code=…&server=…          the QR-free enrolment link
#
# The other two the client parses -- openidx://qr-login and openidx://approve --
# arrive INSIDE the app, from the camera scanner and from a notification tap,
# and need no OS routing.
#
# Android routes both via committed intent-filters in
# client/android/app/src/main/AndroidManifest.xml. iOS routed NEITHER: it needs
# a CFBundleURLTypes entry in ios/Runner/Info.plist, client/.gitignore excludes
# /ios/ because `flutter create` generates it, and nothing put the entry back.
# So the iOS build this project publishes on every release could complete the
# browser half of a login and never receive the redirect -- the last step of the
# sign-in flow, missing, on a build that compiles and analyzes clean.
#
# WHY A PATCH RATHER THAN A COMMITTED Info.plist. The Android manifest is
# committed because `flutter create` does not overwrite an existing file. The
# same trick would work here, but an Info.plist is mostly Flutter's -- bundle
# name, orientations, launch storyboard, the lot -- and a hand-written copy
# drifts from whatever the pinned Flutter version generates, breaking things
# that have nothing to do with deep links. Patching what Flutter just generated
# adds one key and cannot drift.
#
# THE SCHEME IS DERIVED, not written here: it is read out of the Android
# manifest, which is the committed declaration of the same thing. If the two
# platforms ever disagree, this script is where it is noticed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PLIST="${1:-$ROOT/client/ios/Runner/Info.plist}"
MANIFEST="$ROOT/client/android/app/src/main/AndroidManifest.xml"

if [ ! -f "$MANIFEST" ]; then
    echo "::error title=No Android manifest::$MANIFEST is missing, so the URL scheme cannot be derived." >&2
    exit 1
fi

# Every android:scheme= in the manifest, minus the https one the <queries> block
# declares for package visibility (that is browser visibility, not our scheme).
SCHEMES="$(grep -o 'android:scheme="[^"]*"' "$MANIFEST" \
    | sed 's/android:scheme="//; s/"$//' \
    | grep -v '^https\?$' \
    | sort -u)"

if [ -z "$SCHEMES" ]; then
    echo "::error title=No custom scheme::$MANIFEST declares no custom android:scheme, so there is nothing to register on iOS." >&2
    exit 1
fi
if [ "$(printf '%s\n' "$SCHEMES" | wc -l)" -ne 1 ]; then
    echo "::error title=Ambiguous scheme::$MANIFEST declares more than one custom scheme:" >&2
    printf '  %s\n' $SCHEMES >&2
    echo "Teach this script which one iOS should register before adding a second." >&2
    exit 1
fi
SCHEME="$SCHEMES"

if [ ! -f "$PLIST" ]; then
    echo "::error title=No iOS Info.plist::$PLIST does not exist. Run this AFTER \`flutter create --platforms=ios …\`; a silent no-op here is how the scheme went unregistered in the first place." >&2
    exit 1
fi

python3 - "$PLIST" "$SCHEME" <<'PYEOF'
import plistlib, sys

path, scheme = sys.argv[1], sys.argv[2]

with open(path, "rb") as f:
    plist = plistlib.load(f)

types = plist.setdefault("CFBundleURLTypes", [])

# Idempotent: CI materializes the runner and patches it on every job, and a
# developer may run this twice. Registering the scheme twice is not an error on
# Apple's side, but a file that grows an entry per run is one nobody can read.
for entry in types:
    if scheme in entry.get("CFBundleURLSchemes", []):
        print("ci-configure-ios-deeplinks: %s already registers %s://" % (path, scheme))
        sys.exit(0)

# CFBundleURLName is deliberately omitted. Apple documents it as an optional
# abstract name and the only required key is CFBundleURLSchemes; inventing an
# identifier here would be a second source of truth for the bundle id.
types.append({"CFBundleURLSchemes": [scheme]})

with open(path, "wb") as f:
    plistlib.dump(plist, f)

print("ci-configure-ios-deeplinks: registered %s:// in %s" % (scheme, path))
PYEOF
