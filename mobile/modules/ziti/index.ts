/**
 * Local Expo native module: OpenZiti embedded endpoint (`OidxZiti`).
 *
 * This is the TS surface of the native module implemented in ios/ (Swift, CZiti)
 * and android/ (Kotlin, ziti-android). It is loaded OPTIONALLY so the JS bundle
 * still runs in builds where the native side isn't compiled in (Expo Go / a
 * dev build without the module) — in that case every method rejects/returns a
 * safe default. The app consumes this via src/features/ziti/native.ts.
 */
import { requireOptionalNativeModule } from 'expo-modules-core';

export type ZitiStatus = 'enrolled' | 'unenrolled' | 'error' | 'unavailable';

export interface OidxZitiModule {
  /** Exchange a Ziti enrollment JWT for an identity, persisted in the OS keystore. */
  enroll(jwt: string): Promise<void>;
  /** Current identity status. */
  status(): Promise<ZitiStatus>;
  /** Whether a named Ziti service is currently dialable for this identity. */
  serviceAvailable(name: string): Promise<boolean>;
  /** Dial a service; resolves to a loopback address (host:port) the app can use. */
  dial(name: string): Promise<string>;
}

const native = requireOptionalNativeModule<OidxZitiModule>('OidxZiti');

export function isNativeZitiAvailable(): boolean {
  return native != null;
}

export default native;
