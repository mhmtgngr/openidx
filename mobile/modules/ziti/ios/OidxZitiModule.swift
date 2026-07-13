import ExpoModulesCore
import CZiti

// OpenIDX embedded OpenZiti endpoint (iOS).
//
// Wraps the CZiti Swift SDK. The identity produced at enrollment is persisted in
// the app keychain (CZiti's ZitiKeychain, keyed by the identity's sub/zid); on
// launch we lazily bring the Ziti context up so serviceAvailable/dial work.
//
// NOTE: CZiti's exact enroll/dial signatures are version-sensitive — pin the
// pod version in OidxZiti.podspec and verify the calls marked `MARK: SDK` below
// against that version before the first EAS build.
public class OidxZitiModule: Module {
  private var ziti: Ziti?
  private let keychainTag = "org.openidx.mobile.ziti"

  public func definition() -> ModuleDefinition {
    Name("OidxZiti")

    // Exchange an enrollment JWT for an identity and persist it.
    AsyncFunction("enroll") { (jwt: String, promise: Promise) in
      // Write the JWT to a temp file — CZiti enrolls from a JWT file path.
      let tmp = FileManager.default.temporaryDirectory
        .appendingPathComponent("oidx-\(UUID().uuidString).jwt")
      do {
        try jwt.write(to: tmp, atomically: true, encoding: .utf8)
      } catch {
        promise.reject("enroll_write", "failed to stage enrollment jwt: \(error.localizedDescription)")
        return
      }

      // MARK: SDK — enroll and persist the resulting identity.
      Ziti.enroll(tmp.path) { [weak self] zid, err in
        try? FileManager.default.removeItem(at: tmp)
        if let err = err {
          promise.reject("enroll_failed", err.localizedDescription)
          return
        }
        guard let zid = zid else {
          promise.reject("enroll_failed", "no identity returned")
          return
        }
        // Persist the enrolled identity to the keychain for reuse across launches.
        let kc = ZitiKeychain(tag: self?.keychainTag ?? "org.openidx.mobile.ziti")
        _ = kc.storeIdentity(zid)
        promise.resolve(nil)
      }
    }

    AsyncFunction("status") { (promise: Promise) in
      let kc = ZitiKeychain(tag: self.keychainTag)
      // MARK: SDK — a stored identity ⇒ enrolled.
      if kc.loadIdentity() != nil {
        promise.resolve("enrolled")
      } else {
        promise.resolve("unenrolled")
      }
    }

    AsyncFunction("serviceAvailable") { (name: String, promise: Promise) in
      self.withZiti(promise) { ziti in
        // MARK: SDK — resolve whether the service is dialable for this identity.
        let available = ziti.services.contains { $0.name == name && ($0.permFlags ?? 0) != 0 }
        promise.resolve(available)
      }
    }

    AsyncFunction("dial") { (name: String, promise: Promise) in
      self.withZiti(promise) { ziti in
        // MARK: SDK — open the service and bridge it to a local loopback socket
        // the WebView / SSH client can connect to. The loopback listener that
        // proxies to conn is intentionally elided from this scaffold (needs a
        // small TCP-accept loop bound to 127.0.0.1:0); return its host:port.
        promise.reject("not_implemented",
          "dial(): bind a 127.0.0.1 loopback proxy to the Ziti conn and return host:port")
        _ = ziti
      }
    }
  }

  // Bring the Ziti context up lazily from the stored identity.
  private func withZiti(_ promise: Promise, _ body: @escaping (Ziti) -> Void) {
    if let ziti = self.ziti {
      body(ziti)
      return
    }
    let kc = ZitiKeychain(tag: self.keychainTag)
    guard let zid = kc.loadIdentity() else {
      promise.reject("unenrolled", "no enrolled Ziti identity")
      return
    }
    let ziti = Ziti(zid: zid)
    self.ziti = ziti
    // MARK: SDK — run() readies services; call body once the context is up.
    ziti.run { err in
      if let err = err {
        promise.reject("ziti_run", err.localizedDescription)
        return
      }
      body(ziti)
    }
  }
}
