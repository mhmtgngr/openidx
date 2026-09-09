#!/usr/bin/env bash
# Self-test for check-mobile-keystore.sh.
#
# The cases that matter are the ones that COMPILE AND RUN. A keystore that is
# really a constant key produces genuine AES-GCM ciphertext with a fresh nonce
# and opens back to the plaintext: it passes the Go self-test on every launch,
# it passes `flutter analyze`, it ships. The only place that mistake is visible
# is the host source, so those are the first two cases here.
#
# The negatives matter as much. A guard that reddens on a correct sealer is one
# somebody switches off.
#
# NOT COVERED HERE, said rather than implied: rule 4, that the sealers are
# tracked by git. Every case below writes fixtures to a temp directory, where
# untracked is the expected state, so the guard turns that rule off whenever the
# path overrides are in use. It is proven against the real tree instead — the
# guard reported exactly that finding on these files before they were added.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-mobile-keystore.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

GO_OK='package mobile

func Start(configDir string, keystore Keystore) error { return nil }
'

GO_IFACE_OK='package mobile

type Keystore interface {
	Wrap(plaintextBase64 string) string
	Unwrap(sealedBase64 string) string
}
'

KT_PLUGIN_OK='class OpenidxEnginePlugin {
  private fun dispatch(call: MethodCall): Any? {
    return when (call.method) {
      "start" -> { Mobile.start(arg(call, "configDir"), AndroidKeystoreSealer()); null }
      "status" -> Mobile.status()
      else -> throw IllegalArgumentException("unimplemented")
    }
  }
}
'

KT_SEALER_OK='class AndroidKeystoreSealer : Keystore {
  private fun key(): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val spec = KeyGenParameterSpec.Builder(ALIAS, PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
    return generator.generateKey()
  }
}
'

SW_PLUGIN_OK='public class OpenidxEnginePlugin: NSObject {
  private func dispatch(_ method: String, _ args: [String: Any]?) throws -> Any? {
    switch method {
    case "start":
      try excludeFromBackup(configDir)
      try callVoid { MobileStart(configDir, KeychainSealer(), $0) }
      return nil
    default:
      throw NSError(domain: "openidx_engine", code: -1)
    }
  }
}
'

SW_SEALER_OK='public class KeychainSealer: NSObject, MobileKeystore {
  private func load() throws -> Data? {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword]
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    return nil
  }
  private func store(_ key: Data) throws {
    let item: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let status = SecItemAdd(item as CFDictionary, nil)
  }
}
'

# case <name> <expected-exit> — writes the five fixtures from the *_OK vars,
# applies the caller's mutation via the env, and runs the guard.
run_case() {
	local name="$1" want="$2"
	shift 2

	local d="$TMP/case-$((PASS + FAIL))"
	mkdir -p "$d"
	printf '%s' "$GO_OK" >"$d/mobile.go"
	printf '%s' "$GO_IFACE_OK" >"$d/keystore.go"
	printf '%s' "$KT_PLUGIN_OK" >"$d/Plugin.kt"
	printf '%s' "$KT_SEALER_OK" >"$d/Sealer.kt"
	printf '%s' "$SW_PLUGIN_OK" >"$d/Plugin.swift"
	printf '%s' "$SW_SEALER_OK" >"$d/Sealer.swift"

	# The mutation, as a shell snippet operating on $d.
	eval "$@"

	local out rc
	out=$(CHECK_MOBILE_KEYSTORE_GO="$d/mobile.go" \
		CHECK_MOBILE_KEYSTORE_GO_IFACE="$d/keystore.go" \
		CHECK_MOBILE_KEYSTORE_KOTLIN_PLUGIN="$d/Plugin.kt" \
		CHECK_MOBILE_KEYSTORE_KOTLIN_SEALER="$d/Sealer.kt" \
		CHECK_MOBILE_KEYSTORE_SWIFT_PLUGIN="$d/Plugin.swift" \
		CHECK_MOBILE_KEYSTORE_SWIFT_SEALER="$d/Sealer.swift" \
		bash "$GUARD" --enforce 2>&1)
	rc=$?

	if [ "$rc" = "$want" ]; then
		PASS=$((PASS + 1))
		echo "  ok   $name (exit $rc)"
	else
		FAIL=$((FAIL + 1))
		echo "  FAIL $name: exit $rc, want $want"
		echo "$out" | sed 's/^/       /'
	fi
}

echo "check-mobile-keystore self-test"

# 1. The tree as it stands.
run_case "the fixed shape passes" 0 ":"

# 2. THE ONE THAT COMPILES AND SHIPS. A key made from bytes the app is holding.
#    Real ciphertext, fresh nonce, perfect round-trip, and the key is in the APK.
run_case "a key built from bytes in the source" 1 \
	'printf "%s" "class AndroidKeystoreSealer : Keystore {
  private fun key() = SecretKeySpec(BuildConfig.SEAL_KEY.toByteArray(), \"AES\")
}
" >"$d/Sealer.kt"'

# 3. The same mistake on iOS: no Keychain at all.
run_case "an iOS sealer that never touches the Keychain" 1 \
	'printf "%s" "public class KeychainSealer: NSObject, MobileKeystore {
  private let key = SymmetricKey(data: Data(repeating: 7, count: 32))
}
" >"$d/Sealer.swift"'

# 4. A Keychain key that IS backed up and CAN be restored onto another phone,
#    which is the difference between a device-bound seal and a portable one.
run_case "a Keychain item without ThisDeviceOnly" 1 \
	'sed -i "s/kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly/kSecAttrAccessibleAfterFirstUnlock/" "$d/Sealer.swift"'

run_case "a Keychain item marked Always" 1 \
	'sed -i "s/kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly/kSecAttrAccessibleAlways/" "$d/Sealer.swift"'

# 5. Start stops requiring a keystore -- the whole control, removed.
run_case "Start no longer takes a Keystore" 1 \
	'printf "%s" "package mobile

func Start(configDir string) error { return nil }
" >"$d/mobile.go"'

# 6. A host that stops passing one. A compile error today; if the boundary ever
#    grew a default, this is what would be left to notice.
run_case "the Kotlin plugin passes no sealer" 1 \
	'sed -i "s/, AndroidKeystoreSealer()//" "$d/Plugin.kt"'

run_case "the Swift plugin passes no sealer" 1 \
	'sed -i "s/, KeychainSealer()//" "$d/Plugin.swift"'

# 7. The interface itself gone.
run_case "no Keystore interface is declared" 1 \
	'printf "%s" "package mobile
" >"$d/keystore.go"'

# 8. A guard whose subject moved must say so, not pass having read nothing.
run_case "a sealer file that is not there" 1 'rm "$d/Sealer.kt"'

echo
echo "check-mobile-keystore self-test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
