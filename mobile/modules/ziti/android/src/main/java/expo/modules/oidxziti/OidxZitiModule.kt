package expo.modules.oidxziti

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.Promise
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.openziti.android.Ziti
import org.openziti.ZitiContext

// OpenIDX embedded OpenZiti endpoint (Android).
//
// Wraps the ziti-android SDK. Enrollment stores the identity in the app's
// Ziti keystore (managed by the SDK); the SDK brings contexts up automatically.
//
// NOTE: the ziti-android enroll/dial API is version-sensitive — pin the version
// in build.gradle and verify the calls marked `SDK:` against it before the
// first EAS build.
class OidxZitiModule : Module() {
  private val scope = CoroutineScope(Dispatchers.IO)

  override fun definition() = ModuleDefinition {
    Name("OidxZiti")

    AsyncFunction("enroll") { jwt: String, promise: Promise ->
      scope.launch {
        try {
          val app = appContext.reactContext?.applicationContext
            ?: throw IllegalStateException("no application context")
          // SDK: enroll from the JWT bytes; the SDK persists the identity.
          Ziti.enroll(app, jwt.toByteArray(Charsets.UTF_8), "openidx")
          promise.resolve(null)
        } catch (e: Throwable) {
          promise.reject("enroll_failed", e.message ?: "enrollment failed", e)
        }
      }
    }

    AsyncFunction("status") { promise: Promise ->
      try {
        // SDK: a present, active context ⇒ enrolled.
        val ctx: ZitiContext? = Ziti.getContexts().firstOrNull()
        promise.resolve(if (ctx != null) "enrolled" else "unenrolled")
      } catch (e: Throwable) {
        promise.resolve("error")
      }
    }

    AsyncFunction("serviceAvailable") { name: String, promise: Promise ->
      try {
        val ctx = Ziti.getContexts().firstOrNull()
        // SDK: check the identity's available services for `name`.
        val available = ctx?.getService(name, 5000) != null
        promise.resolve(available)
      } catch (e: Throwable) {
        promise.resolve(false)
      }
    }

    AsyncFunction("dial") { name: String, promise: Promise ->
      // SDK: open a Ziti connection to the service and bridge it to a local
      // 127.0.0.1 loopback ServerSocket the WebView / SSH client connects to;
      // return that host:port. The loopback proxy loop is intentionally elided
      // from this scaffold.
      promise.reject(
        "not_implemented",
        "dial(): bridge ctx.dial(name) to a 127.0.0.1 loopback socket and return host:port",
        null,
      )
    }
  }
}
