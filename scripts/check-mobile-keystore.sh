#!/usr/bin/env bash
# The engine's credentials on a phone are sealed with a key held by the platform
# keystore, and the implementation of that seal is host code — Kotlin and Swift —
# that no Go build ever sees. This guard reads it.
#
# WHAT THE GO SIDE ALREADY COVERS, so that this only claims what it adds.
# agent/mobile.Start takes the keystore as a parameter with no overload that
# omits it, so a host cannot forget to pass one: that is a compile error, in two
# languages. And before the engine touches a credential,
# agent/internal/secretfile.SelfTest wraps a probe and refuses to start unless
# the result differs from the plaintext, does not CONTAIN the plaintext, opens
# back to it, and differs again on a second wrap. Between them, "no keystore",
# "a stub", "a header round the secret" and "a fixed nonce" are all caught at
# runtime on every launch.
#
# WHAT NEITHER CAN SEE. A perfectly good AES-GCM implementation whose key is a
# constant in the source, or one derived from something on the file system,
# passes every check above — the bytes are real ciphertext, freshly nonced, and
# they round-trip. It is also completely useless, because the key is sitting
# next to the file it protects. The whole property being bought here is WHERE
# THE KEY LIVES, and that is a fact about the host source and nowhere else. So:
#
#   1. Kotlin: the key comes from the "AndroidKeyStore" provider, built with a
#      KeyGenParameterSpec, and is never a SecretKeySpec — which is how you make
#      a key out of bytes you are holding.
#   2. Swift: the key is a Keychain item (SecItemAdd / SecItemCopyMatching) whose
#      accessibility class ends ThisDeviceOnly, so it is in no backup and cannot
#      be restored onto another phone. kSecAttrAccessibleAlways is refused: it is
#      deprecated and it is backed up.
#   3. Both plugins hand a sealer to the engine at start. This is a compile error
#      today, but the check costs a line and states the shape the file is meant
#      to have.
#   4. Both sealers are TRACKED BY GIT. The lesson from
#      check-mobile-secrets-at-rest.sh: a file that exists only in one working
#      copy protects nothing in a build from a clean checkout.
#
# NOT COVERED, said rather than implied: that the seal is randomised. It is
# checkable at runtime and not by reading — Cipher.init decides the IV by which
# overload is called — and SelfTest already refuses a deterministic keystore on
# every launch, which is stronger than a grep.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENFORCE=0
[ "${1:-}" = "--enforce" ] && ENFORCE=1

GO_BOUNDARY="${CHECK_MOBILE_KEYSTORE_GO:-agent/mobile/mobile.go}"
GO_IFACE="${CHECK_MOBILE_KEYSTORE_GO_IFACE:-agent/mobile/keystore.go}"
KOTLIN_PLUGIN="${CHECK_MOBILE_KEYSTORE_KOTLIN_PLUGIN:-client/plugins/openidx_engine/android/src/main/kotlin/org/openidx/engine/OpenidxEnginePlugin.kt}"
KOTLIN_SEALER="${CHECK_MOBILE_KEYSTORE_KOTLIN_SEALER:-client/plugins/openidx_engine/android/src/main/kotlin/org/openidx/engine/AndroidKeystoreSealer.kt}"
SWIFT_PLUGIN="${CHECK_MOBILE_KEYSTORE_SWIFT_PLUGIN:-client/plugins/openidx_engine/ios/Classes/OpenidxEnginePlugin.swift}"
SWIFT_SEALER="${CHECK_MOBILE_KEYSTORE_SWIFT_SEALER:-client/plugins/openidx_engine/ios/Classes/KeychainSealer.swift}"

# The tracked-by-git rule applies to the real tree only; the self-test writes its
# fixtures to a temp directory where untracked is the expected state.
TRACKED_CHECK=1
for var in CHECK_MOBILE_KEYSTORE_GO CHECK_MOBILE_KEYSTORE_GO_IFACE \
	CHECK_MOBILE_KEYSTORE_KOTLIN_PLUGIN CHECK_MOBILE_KEYSTORE_KOTLIN_SEALER \
	CHECK_MOBILE_KEYSTORE_SWIFT_PLUGIN CHECK_MOBILE_KEYSTORE_SWIFT_SEALER; do
	[ -n "${!var:-}" ] && TRACKED_CHECK=0
done
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || TRACKED_CHECK=0

python3 - "$ENFORCE" "$TRACKED_CHECK" \
	"$GO_BOUNDARY" "$GO_IFACE" \
	"$KOTLIN_PLUGIN" "$KOTLIN_SEALER" \
	"$SWIFT_PLUGIN" "$SWIFT_SEALER" <<'PYEOF'
import os
import re
import subprocess
import sys

enforce = sys.argv[1] == "1"
tracked_check = sys.argv[2] == "1"
go_boundary, go_iface, kt_plugin, kt_sealer, sw_plugin, sw_sealer = sys.argv[3:9]

findings = []
checked = 0


def report(where, what, fix):
    findings.append((where, what, fix))


def read(path):
    """Returns the file's text, or None after reporting that it is missing. A
    guard whose subject has moved must say so rather than pass having read
    nothing."""
    global checked
    if not os.path.exists(path):
        report(path, "does not exist, so nothing about it was checked",
               "point the guard at the new path rather than dropping the rule")
        return None
    checked += 1
    if tracked_check:
        rc = subprocess.call(["git", "ls-files", "--error-unmatch", "--", path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rc != 0:
            report(path,
                   "exists on disk but is NOT TRACKED BY GIT, so it is absent from every "
                   "clean checkout and from the build",
                   "`git add` it")
    return open(path, encoding="utf-8").read()


def require(path, src, needle, what, fix, regex=False):
    if src is None:
        return
    found = re.search(needle, src) if regex else (needle in src)
    if not found:
        report(path, what, fix)


def forbid(path, src, needle, what, fix):
    if src is not None and needle in src:
        report(path, what, fix)


# --- the Go boundary --------------------------------------------------------

src = read(go_boundary)
require(go_boundary, src,
        r"func\s+Start\(\s*\w+\s+string\s*,\s*\w+\s+Keystore\s*\)\s*error",
        "Start does not take a Keystore. The control is that there is NO signature "
        "of Start that omits it, so a host cannot start the engine and have it write "
        "credentials in the clear",
        "restore `func Start(configDir string, keystore Keystore) error`",
        regex=True)

src = read(go_iface)
require(go_iface, src, "type Keystore interface",
        "declares no Keystore interface for the host to implement",
        "declare it; gomobile binds it in reverse into a Java interface and an ObjC protocol")

# --- Android ----------------------------------------------------------------

src = read(kt_plugin)
# `.*` and not `[^)]*`: the argument list contains a nested call
# (`arg(call, "configDir")`), and re.search without DOTALL keeps this on one line.
require(kt_plugin, src, r"Mobile\.start\(.*Sealer\(\)",
        "the \"start\" arm does not hand a sealer to Mobile.start",
        "pass AndroidKeystoreSealer() as the second argument",
        regex=True)

src = read(kt_sealer)
require(kt_sealer, src, '"AndroidKeyStore"',
        "never names the \"AndroidKeyStore\" provider, so whatever key it uses is not one "
        "the OS is holding",
        'obtain the key from KeyStore.getInstance("AndroidKeyStore")')
require(kt_sealer, src, "KeyGenParameterSpec",
        "does not build its key with a KeyGenParameterSpec, which is the only way to "
        "generate a non-exportable key in the AndroidKeyStore provider",
        "generate the key with KeyGenParameterSpec.Builder")
forbid(kt_sealer, src, "SecretKeySpec",
       "builds a key with SecretKeySpec — that is a key made from bytes THIS CODE IS "
       "HOLDING, which is the one thing a keystore-backed seal must not be. It produces "
       "real ciphertext and passes every runtime self-test while leaving the key beside "
       "the file it protects",
       "take the key from the AndroidKeyStore provider instead")

# --- iOS --------------------------------------------------------------------

src = read(sw_plugin)
require(sw_plugin, src, r"MobileStart\([^)]*Sealer\(\)",
        "the \"start\" case does not hand a sealer to MobileStart",
        "pass KeychainSealer() as the second argument",
        regex=True)

src = read(sw_sealer)

# gomobile emits a protocol AND a class with the same spelling for a
# reverse-bindable interface -- legal in ObjC, one namespace in Swift, which
# resolves the bare name to the CLASS. Conforming to `MobileKeystore` fails with
# "Multiple inheritance from classes 'NSObject' and 'MobileKeystore'", which
# reads like a design mistake in the sealer and is really a name collision; the
# Clang importer exposes the protocol with a `Protocol` suffix. The compiler
# does catch this -- on a macOS runner, ~25 minutes in, with that message. Here
# it is a line of grep, and the fix is named.
if src is not None and re.search(r":\s*NSObject\s*,\s*MobileKeystore\b(?!Protocol)", src):
    report(sw_sealer,
           "conforms to `MobileKeystore`, which Swift resolves to gomobile's generated "
           "CLASS of that name rather than the protocol beside it",
           "conform to `MobileKeystoreProtocol` (see the comment at the top of the file; "
           "`go tool gobind -lang=objc` from agent/ prints both declarations)")

for api in ("SecItemAdd", "SecItemCopyMatching", "kSecClass"):
    require(sw_sealer, src, api,
            "never calls %s, so its key is not a Keychain item" % api,
            "store and load the key through the Keychain")
require(sw_sealer, src, r"kSecAttrAccessible\w*ThisDeviceOnly",
        "does not use a ThisDeviceOnly accessibility class, so the key goes into the "
        "user's backup and can be restored onto another phone together with the sealed "
        "files it opens",
        "use kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        regex=True)
forbid(sw_sealer, src, "kSecAttrAccessibleAlways",
       "uses kSecAttrAccessibleAlways, which is deprecated and is included in backups",
       "use kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly")

if checked == 0:
    print("check-mobile-keystore: examined no file at all. A guard reading nothing "
          "passes vacuously, which is the failure it exists to catch.", file=sys.stderr)
    sys.exit(1 if enforce else 0)

if not findings:
    print("check-mobile-keystore: ok — %d file(s): Start requires a Keystore, and both "
          "hosts seal with a key the OS holds rather than one in the source" % checked)
    sys.exit(0)

print()
for where, what, fix in findings:
    print("%s" % where, file=sys.stderr)
    print("    %s" % what, file=sys.stderr)
    print("    fix: %s" % fix, file=sys.stderr)
print(file=sys.stderr)
print("check-mobile-keystore: %d finding(s). The runtime self-test proves the seal is a "
      "seal; only the source says where the key lives." % len(findings), file=sys.stderr)
sys.exit(1 if enforce else 0)
PYEOF
