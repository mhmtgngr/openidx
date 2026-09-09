import CryptoKit
import Foundation
import Security

// `MobileKeystoreProtocol` is the ObjC protocol produced by
//   gomobile bind -target=ios -o Engine.xcframework ./agent/mobile
// from the Go interface `Keystore` in package `mobile` (the module is named
// after -o, the prefix after the package). Conforming to it here is what lets
// Go call OUT into iOS — the reverse of every other call across this boundary.
//
// THE `Protocol` SUFFIX IS NOT A TYPO, and writing the obvious name instead is
// a build failure with a misleading message. For a reverse-bindable interface
// gomobile emits TWO things with the same spelling:
//
//     @protocol MobileKeystore <NSObject>
//     @interface MobileKeystore : NSObject <goSeqRefInterface, MobileKeystore>
//
// (the class is how a Go-side implementation is handed to ObjC). Objective-C
// keeps classes and protocols in separate namespaces, so that is legal there.
// Swift has one namespace, resolves the bare name to the CLASS, and reports
// `Multiple inheritance from classes 'NSObject' and 'MobileKeystore'` — an
// error that reads like a design mistake in this file and is really a name
// collision. The Clang importer exposes the protocol with a `Protocol` suffix.
//
// To see the generated declarations without a Mac: from agent/,
//   go tool gobind -lang=objc -outdir=/tmp/gb ./mobile
// and read /tmp/gb/src/gobind/Mobile.objc.h.
import Engine

/// Seals the engine's credentials with a key held by the iOS Keychain.
///
/// WHAT THIS IS FOR. Everything the engine writes into
/// `Library/Application Support` is a credential: user-tokens.json holds the
/// 30-day refresh token, agent.json the agent's own auth token. The app
/// container keeps other apps out, and `isExcludedFromBackup` on the directory
/// keeps those files out of iCloud and out of every iTunes backup. None of that
/// helps once something is reading the file system directly — a jailbroken
/// phone, or an extraction from one that is merely unlocked — because the
/// default protection class for that directory is
/// `NSFileProtectionCompleteUntilFirstUserAuthentication`: decrypted at the
/// first unlock after boot and left decrypted while the device is on. "At rest"
/// there means readable.
///
/// WHAT THE KEY BUYS, said plainly. The key is a random 256-bit AES key stored
/// as a Keychain item with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`:
///
///   - ThisDeviceOnly — it is in no backup and cannot be restored onto another
///     device, so the sealed files are useless once copied off this phone.
///   - AfterFirstUnlock rather than WhenUnlocked — the background posture report
///     and the push-approval fetch have to work with the phone in a pocket, and
///     a key that is unavailable while locked would fail those rather than
///     protect them.
///
/// It is NOT a Secure Enclave key. The Enclave holds P-256 keys, not AES ones,
/// and the ECIES path around them is a second code path that would only run on
/// hardware — the simulator has no Enclave — so the one that ships would be the
/// one CI never builds. What this buys is that the key lives in the Keychain,
/// behind a hardware-derived class key, and not in the container the ciphertext
/// sits in; what it does not buy is resistance to a jailbreak that dumps the
/// Keychain itself. Saying which is which beats implying the stronger one.
///
/// THE CONTRACT, which the Go side checks at Start before the engine touches a
/// credential (agent/internal/secretfile.SelfTest):
///
///   - `unwrap(wrap(x))` is `x`.
///   - `wrap` is randomised — AES.GCM.seal takes a fresh nonce per call, so the
///     same token sealed twice gives different bytes.
///   - `wrap(x)` does not contain `x`. A "seal" that prefixes a header would
///     round-trip perfectly and leave the refresh token in the file in full.
///
/// Failing any of them means the engine refuses to start rather than write a
/// credential in the clear.
public class KeychainSealer: NSObject, MobileKeystoreProtocol {

  private static let account = "org.openidx.engine.secrets.v1"
  private static let service = "org.openidx.engine"

  public func wrap(_ plaintextBase64: String?) -> String {
    return reply {
      guard let encoded = plaintextBase64,
            let plaintext = Data(base64Encoded: encoded, options: [.ignoreUnknownCharacters])
      else { throw SealError.notBase64 }
      // combined is nonce || ciphertext || tag, and the nonce is freshly
      // generated per call, which is what makes the seal non-deterministic.
      let sealingKey = try key()
      let sealed = try AES.GCM.seal(plaintext, using: sealingKey)
      guard let combined = sealed.combined else { throw SealError.noCombinedForm }
      return combined
    }
  }

  public func unwrap(_ sealedBase64: String?) -> String {
    return reply {
      guard let encoded = sealedBase64,
            let blob = Data(base64Encoded: encoded, options: [.ignoreUnknownCharacters])
      else { throw SealError.notBase64 }
      let openingKey = try key()
      let box = try AES.GCM.SealedBox(combined: blob)
      return try AES.GCM.open(box, using: openingKey)
    }
  }

  /// Returns the app's sealing key, creating and storing it on first use.
  ///
  /// Go calls in from its own goroutines — a token refresh and a posture report
  /// can seal at the same moment — so two threads can both find no key and both
  /// generate one. Rather than lock, the loser is recovered: SecItemAdd reports
  /// errSecDuplicateItem instead of overwriting, and the key already in the
  /// Keychain is the one that opens whatever has been sealed. Silently keeping
  /// the second key would make every file written under the first unreadable.
  private func key() throws -> SymmetricKey {
    if let existing = try load() {
      return SymmetricKey(data: existing)
    }
    var fresh = Data(count: 32)
    let status = fresh.withUnsafeMutableBytes { buf -> OSStatus in
      guard let base = buf.baseAddress else { return errSecAllocate }
      return SecRandomCopyBytes(kSecRandomDefault, 32, base)
    }
    guard status == errSecSuccess else { throw SealError.keychain(status) }
    do {
      try store(fresh)
    } catch SealError.keychain(let status) where status == errSecDuplicateItem {
      guard let winner = try load() else { throw SealError.corruptKey }
      return SymmetricKey(data: winner)
    }
    return SymmetricKey(data: fresh)
  }

  private func load() throws -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: Self.account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    switch status {
    case errSecSuccess:
      guard let data = item as? Data, data.count == 32 else { throw SealError.corruptKey }
      return data
    case errSecItemNotFound:
      return nil
    default:
      throw SealError.keychain(status)
    }
  }

  private func store(_ key: Data) throws {
    let item: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: Self.account,
      kSecValueData as String: key,
      // ThisDeviceOnly keeps it out of every backup and off every other device;
      // AfterFirstUnlock keeps the background work that needs it running.
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let status = SecItemAdd(item as CFDictionary, nil)
    guard status == errSecSuccess else { throw SealError.keychain(status) }
  }

  /// Runs `body` and renders its outcome in the boundary's tagged form:
  /// `ok:<base64>` or `error:<message>`.
  ///
  /// The message carries the failure and never the value being sealed: the
  /// engine writes its errors to control.log, which lives in the same directory
  /// as the credentials this is protecting.
  private func reply(_ body: () throws -> Data) -> String {
    do {
      return "ok:" + (try body()).base64EncodedString()
    } catch {
      return "error:\(error)"
    }
  }

  private enum SealError: Error, CustomStringConvertible {
    case notBase64
    case noCombinedForm
    case corruptKey
    case keychain(OSStatus)

    var description: String {
      switch self {
      case .notBase64:
        return "the argument was not standard base64"
      case .noCombinedForm:
        return "AES.GCM produced no combined representation"
      case .corruptKey:
        return "the stored keychain item is not a 32-byte key"
      case .keychain(let status):
        return "keychain error \(status)"
      }
    }
  }
}
