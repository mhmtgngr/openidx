#!/usr/bin/env python3
"""Register the `openidx://` URL scheme in the generated platform runners.

`client/` does not commit `android/` or `ios/`; CI materializes them with
`flutter create` before every build (see .github/workflows/client-mobile-*.yml).
That template knows nothing about our custom scheme, so without this step the app
ships with no VIEW intent filter / no CFBundleURLTypes and the OS never routes
`openidx://` to it — `adb shell cmd package resolve-activity -d openidx://…`
answers "No activity found".

Three shipped features depend on the scheme:
  * openidx://enroll?code=..&server=..  — admin-console enrollment link
  * openidx://oauth-callback?code=..    — browser PKCE fallback redirect
  * openidx://approve/<challengeId>     — push-approval deep link

Run after `flutter create`, from the `client/` directory. Idempotent: patching an
already-patched runner is a no-op, so re-running (or a partially cached
checkout) is safe.
"""

from __future__ import annotations

import plistlib
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEME = "openidx"
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _android_attr(name: str) -> str:
    return f"{{{ANDROID_NS}}}{name}"


def patch_android(manifest: Path) -> bool:
    """Add a VIEW/BROWSABLE intent-filter for SCHEME to the launcher activity.

    Returns True if the file was modified.
    """
    ET.register_namespace("android", ANDROID_NS)
    tree = ET.parse(manifest)
    root = tree.getroot()

    activity = root.find("./application/activity")
    if activity is None:
        raise SystemExit(f"{manifest}: no <activity> found")

    # Already patched? Look for a <data android:scheme="openidx"/> anywhere in
    # the activity's existing filters.
    for data in activity.iterfind("./intent-filter/data"):
        if data.get(_android_attr("scheme")) == SCHEME:
            return False

    filt = ET.SubElement(activity, "intent-filter")
    ET.SubElement(filt, "action").set(
        _android_attr("name"), "android.intent.action.VIEW"
    )
    for category in ("android.intent.category.DEFAULT",
                     "android.intent.category.BROWSABLE"):
        ET.SubElement(filt, "category").set(_android_attr("name"), category)
    ET.SubElement(filt, "data").set(_android_attr("scheme"), SCHEME)

    ET.indent(tree, space="    ")
    tree.write(manifest, encoding="utf-8", xml_declaration=True)
    return True


def patch_ios(info_plist: Path) -> bool:
    """Add SCHEME to CFBundleURLTypes. Returns True if the file was modified."""
    with info_plist.open("rb") as fh:
        plist = plistlib.load(fh)

    url_types = plist.setdefault("CFBundleURLTypes", [])
    for entry in url_types:
        if SCHEME in entry.get("CFBundleURLSchemes", []):
            return False

    url_types.append({
        "CFBundleTypeRole": "Editor",
        "CFBundleURLName": "org.openidx.client",
        "CFBundleURLSchemes": [SCHEME],
    })
    with info_plist.open("wb") as fh:
        plistlib.dump(plist, fh)
    return True


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    patched = []

    manifest = root / "android/app/src/main/AndroidManifest.xml"
    if manifest.exists():
        patched.append(f"android: {'patched' if patch_android(manifest) else 'already present'}")

    info_plist = root / "ios/Runner/Info.plist"
    if info_plist.exists():
        patched.append(f"ios: {'patched' if patch_ios(info_plist) else 'already present'}")

    if not patched:
        raise SystemExit(
            f"{root}: neither android/ nor ios/ found — run `flutter create` first"
        )
    print(f"{SCHEME}:// scheme — " + ", ".join(patched))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
