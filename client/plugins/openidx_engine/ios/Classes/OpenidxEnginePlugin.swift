import Flutter
import Foundation
import UIKit

// `Engine` is the Swift module produced by
//   gomobile bind -target=ios -o Engine.xcframework ./agent/mobile
// gomobile names the module after the -o output (Engine), while the Go package
// (`mobile`) determines the function PREFIX — so the module is `Engine` but the
// funcs are `Mobile<Func>`. The funcs use the gomobile calling convention:
// value-returning funcs take an `NSErrorPointer` out-param and return the
// String; error-only funcs return (throw) an error. See README.md.
import Engine

public class OpenidxEnginePlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(
      name: "openidx_engine",
      binaryMessenger: registrar.messenger())
    let instance = OpenidxEnginePlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    let args = call.arguments as? [String: Any]

    // Run the Go bridge off the platform thread: ZitiDial and login can block
    // on network I/O, and we must never stall the UI/main thread.
    DispatchQueue.global(qos: .userInitiated).async {
      do {
        let value = try self.dispatch(call.method, args)
        DispatchQueue.main.async { result(value) }
      } catch let err as NSError {
        DispatchQueue.main.async {
          result(FlutterError(
            code: "engine_error",
            message: err.localizedDescription,
            details: "\(err.domain)#\(err.code)"))
        }
      }
    }
  }

  /// Maps a channel method name to the corresponding gomobile function. Returns
  /// the JSON string (or `nil` for void methods). Throws the Go error, which
  /// `handle` converts into a `FlutterError`.
  private func dispatch(_ method: String, _ args: [String: Any]?) throws -> Any? {
    switch method {
    case "start":
      let configDir = str(args, "configDir")
      // Before the engine writes anything, not after: the flag is a property of
      // the directory, and a backup that ran between the first write and a later
      // call would already have taken the tokens.
      try excludeFromBackup(configDir)
      // The sealer is constructed HERE and not passed down from Dart: a key the
      // Dart layer could hold is a key in the app's own heap, which is the thing
      // the Keychain exists to avoid. Go calls back into it for every credential
      // it writes, and refuses to start if it does not actually seal.
      try callVoid { MobileStart(configDir, KeychainSealer(), $0) }
      return nil
    case "setServer":
      try callVoid { MobileSetServer(str(args, "url"), $0) }
      return nil
    case "status":
      return try callString { MobileStatus($0) }
    case "login":
      return try callString { MobileLogin($0) }
    case "loginStart":
      return try callString { MobileLoginStart($0) }
    case "loginFinish":
      return try callString { MobileLoginFinish(str(args, "callbackUrl"), $0) }
    case "accessToken":
      return try callString { MobileAccessToken($0) }
    case "deviceState":
      return try callString { MobileDeviceState($0) }
    case "logout":
      try callVoid { MobileLogout($0) }
      return nil
    case "enroll":
      let code = str(args, "code")
      return try callString { MobileEnroll(code, $0) }
    case "registerPushDevice":
      let deviceToken = str(args, "deviceToken")
      let platform = str(args, "platform")
      return try callString { MobileRegisterPushDevice(deviceToken, platform, $0) }
    case "posture":
      return try callString { MobilePosture($0) }
    case "pamList":
      return try callString { MobilePamList($0) }
    case "pamConnect":
      let entryID = str(args, "entryId")
      return try callString { MobilePamConnect(entryID, $0) }
    case "pamRequest":
      try callVoid { MobilePamRequest(str(args, "entryId"), str(args, "reason"), $0) }
      return nil
    case "zitiDial":
      let service = str(args, "service")
      return try callString { MobileZitiDial(service, $0) }
    case "zitiClose":
      try callVoid { MobileZitiClose(str(args, "service"), $0) }
      return nil
    case "logs":
      return try callString { MobileLogs($0) }
    default:
      throw NSError(
        domain: "openidx_engine",
        code: -1,
        userInfo: [NSLocalizedDescriptionKey: "unimplemented method \(method)"])
    }
  }

  /// Marks the engine's config directory as excluded from iCloud and iTunes
  /// backups.
  ///
  /// The Flutter side hands us `getApplicationSupportDirectory()`, which is
  /// `Library/Application Support` — inside the backup set. Everything the
  /// engine writes there is a credential or derived from one: agent.json (the
  /// agent auth token), user-tokens.json (the access token and the 30-day
  /// refresh token behind it) and ziti-identity.json (the private key and
  /// certificates that put this device on the ZTNA overlay). Without this flag
  /// they are in the user's iCloud backup and in every unencrypted iTunes
  /// backup on a machine they have ever synced to.
  ///
  /// The Go code writes those files 0600. On a Linux desktop that mode IS the
  /// protection; in an iOS app container it is inert — the sandbox already makes
  /// them private, and a mode bit says nothing about what the backup takes out.
  ///
  /// The flag is set on the directory, which covers its contents, and it must be
  /// set on a path that exists — so the directory is created first if the app has
  /// not run before. Losing the config on a restored device is the intended
  /// outcome: a restore lands on different hardware, and re-enrolling is how the
  /// server gets to decide whether to trust it.
  private func excludeFromBackup(_ path: String) throws {
    // An empty path is a bug in the Dart layer, and URL(fileURLWithPath: "")
    // resolves to the working directory — so flagging it would "succeed" while
    // protecting nothing. Refuse instead: the engine cannot start without a
    // config directory anyway, and this names the reason.
    guard !path.isEmpty else {
      throw NSError(
        domain: "openidx_engine",
        code: -2,
        userInfo: [NSLocalizedDescriptionKey: "configDir is empty; cannot start the engine"])
    }
    // withIntermediateDirectories: true is a no-op when the directory is already
    // there, so this needs no existence check and cannot race one.
    try FileManager.default.createDirectory(
      atPath: path, withIntermediateDirectories: true, attributes: nil)
    var url = URL(fileURLWithPath: path)
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try url.setResourceValues(values)
  }

  /// Invokes a gomobile `(String, error)` func using the `NSErrorPointer`
  /// convention and rethrows the error as a Swift throw.
  private func callString(_ body: (NSErrorPointer) -> String) throws -> String {
    var error: NSError?
    let value = body(&error)
    if let error = error { throw error }
    return value
  }

  /// Invokes a gomobile error-only func. gomobile generates these as
  /// `BOOL MobileX(..., NSError**)` (success flag + out-param), NOT as Swift
  /// `throws`, so we pass the NSErrorPointer explicitly, discard the BOOL, and
  /// rethrow any error.
  private func callVoid(_ body: (NSErrorPointer) -> Bool) throws {
    var error: NSError?
    _ = body(&error)
    if let error = error { throw error }
  }

  private func str(_ args: [String: Any]?, _ key: String) -> String {
    return (args?[key] as? String) ?? ""
  }
}
