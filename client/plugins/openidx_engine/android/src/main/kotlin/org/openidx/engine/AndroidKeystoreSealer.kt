package org.openidx.engine

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

// `mobile.Keystore` is the Java interface produced by
//   gomobile bind -target=android -o engine.aar ./agent/mobile
// from the Go interface of the same name. Implementing it here is what lets Go
// call OUT into Android — the reverse of every other call across this boundary.
import mobile.Keystore

/**
 * Seals the engine's credentials with a key held by the Android Keystore.
 *
 * WHAT THIS IS FOR. Everything the engine writes into the app's files directory
 * is a credential: user-tokens.json holds the 30-day refresh token, agent.json
 * the agent's own auth token. The sandbox keeps other apps out, and
 * `android:allowBackup="false"` plus dataExtractionRules keep those files out of
 * Google Drive and out of a device-to-device transfer. None of that helps once
 * something is reading the file system directly — a rooted phone, a custom
 * recovery, an extraction from a device that is merely unlocked — because
 * credential-encrypted storage is decrypted at the first unlock after boot and
 * stays decrypted while the device is on. "At rest" there means readable.
 *
 * WHY THE KEY IS NOT PASSED TO GO. A key generated in the AndroidKeyStore
 * provider is non-exportable: `SecretKey.getEncoded()` returns null for it, and
 * on hardware with a TEE or a StrongBox the material never leaves that boundary
 * at all. So Go cannot be handed the key; it is handed the two operations, and
 * the key stays where the file system is not. That is the whole point, and it
 * is why the Go side takes an interface rather than a byte array.
 *
 * NO USER AUTHENTICATION IS REQUIRED ON THE KEY, deliberately. Setting
 * `setUserAuthenticationRequired(true)` would put a biometric prompt in front of
 * every token read, including the background posture report and the push-approval
 * fetch that must work while the phone is in a pocket. The property being bought
 * here is that the key is not in the file system, not that the user is present.
 *
 * THE CONTRACT, which the Go side checks at Start before the engine touches a
 * credential (agent/internal/secretfile.SelfTest):
 *
 *  - `unwrap(wrap(x))` is `x`.
 *  - `wrap` is randomised — GCM gets a fresh IV per call, so the same token
 *    sealed twice gives different bytes.
 *  - `wrap(x)` does not contain `x`. A "seal" that prefixes a header would
 *    round-trip perfectly and leave the refresh token in the file in full.
 *
 * Failing any of them means the engine refuses to start rather than write a
 * credential in the clear, so a mistake here is a launch failure with a message
 * and not a phone quietly holding a plaintext refresh token.
 */
class AndroidKeystoreSealer : Keystore {

  override fun wrap(plaintextBase64: String): String = reply {
    val plaintext = Base64.decode(plaintextBase64, Base64.DEFAULT)
    val cipher = Cipher.getInstance(TRANSFORMATION)
    // No IV is supplied: the provider generates a fresh one per call, which is
    // both the correct GCM discipline and what makes the seal non-deterministic.
    cipher.init(Cipher.ENCRYPT_MODE, key())
    val iv = cipher.iv
    val body = cipher.doFinal(plaintext)
    iv + body
  }

  override fun unwrap(sealedBase64: String): String = reply {
    val sealed = Base64.decode(sealedBase64, Base64.DEFAULT)
    require(sealed.size > IV_BYTES) { "sealed blob is too short to carry an IV" }
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(
      Cipher.DECRYPT_MODE,
      key(),
      GCMParameterSpec(TAG_BITS, sealed, 0, IV_BYTES))
    cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES)
  }

  /**
   * Returns the app's sealing key, creating it on first use.
   *
   * StrongBox is asked for and not insisted on: devices without the dedicated
   * security chip throw [android.security.keystore.StrongBoxUnavailableException]
   * from generateKey(), and a TEE-backed key on those is the best the hardware
   * offers. Refusing to run there would take the control away from the phones
   * that need it most.
   *
   * SYNCHRONIZED, and the reason is not throughput. Go calls in from its own
   * goroutines — a token refresh and a posture report can seal at the same
   * moment — and KeyGenerator.generateKey() on an alias that already exists
   * REPLACES the key rather than failing. Two threads finding no key and both
   * generating would leave one of them holding a key that no longer opens what
   * it just sealed, and every file written before the loser's key would become
   * unreadable: the user is signed out and the device un-enrolled, with nothing
   * to see but a decryption error. The lock is on the class rather than the
   * instance because the alias is shared by any instance that exists.
   */
  private fun key(): SecretKey = synchronized(lock) {
    val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
    (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey?.let { return it }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      try {
        return generate(strongBox = true)
      } catch (e: Exception) {
        // No StrongBox on this device (or it is out of key slots). Fall through
        // to the TEE-backed key rather than failing the launch.
      }
    }
    return generate(strongBox = false)
  }

  private fun generate(strongBox: Boolean): SecretKey {
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
    val spec = KeyGenParameterSpec.Builder(
      ALIAS,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
    if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      spec.setIsStrongBoxBacked(true)
    }
    generator.init(spec.build())
    return generator.generateKey()
  }

  /**
   * Runs [body] and renders its outcome in the boundary's tagged form:
   * `ok:<base64>` or `error:<message>`. NO_WRAP because the Go side decodes
   * standard base64 and Android's encoder line-wraps by default.
   *
   * The message carries the exception's type and text and never the value being
   * sealed: the engine writes its errors to control.log, which lives in the same
   * directory as the credentials this is protecting.
   */
  private inline fun reply(body: () -> ByteArray): String =
    try {
      "ok:" + Base64.encodeToString(body(), Base64.NO_WRAP)
    } catch (e: Exception) {
      "error:${e.javaClass.simpleName}: ${e.message ?: "no detail"}"
    }

  private companion object {
    val lock = Any()
    const val PROVIDER = "AndroidKeyStore"
    const val ALIAS = "org.openidx.engine.secrets.v1"
    const val TRANSFORMATION = "AES/GCM/NoPadding"
    const val IV_BYTES = 12
    const val TAG_BITS = 128
  }
}
