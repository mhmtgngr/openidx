/**
 * Thin wrapper over the native OpenZiti module.
 *
 * The actual embedded-overlay endpoint is a native Expo module (`OidxZiti`,
 * Swift/Kotlin wrapping the OpenZiti mobile SDK) that must be added and built
 * via EAS with the SDK dependency — it cannot run in Expo Go / a JS-only build.
 * We load it optionally so the whole app still builds and runs with Ziti
 * features gracefully disabled until the native module is present.
 *
 * Native module surface (to implement in modules/ziti/, per the plan):
 *   enroll(jwt: string): Promise<void>      // exchange ziti_jwt -> identity, store in Keychain/Keystore
 *   status(): Promise<'enrolled'|'unenrolled'|'error'>
 *   serviceAvailable(name: string): Promise<boolean>
 *   dial(name: string): Promise<string>     // returns a loopback address the WebView/SSH can use
 */
import { requireOptionalNativeModule } from 'expo-modules-core';

type ZitiNative = {
  enroll(jwt: string): Promise<void>;
  status(): Promise<string>;
  serviceAvailable(name: string): Promise<boolean>;
  dial(name: string): Promise<string>;
};

const Native = requireOptionalNativeModule<ZitiNative>('OidxZiti');

export function zitiAvailable(): boolean {
  return Native != null;
}

export async function zitiEnroll(jwt: string): Promise<void> {
  if (!Native) throw new Error('OpenZiti native module not installed in this build');
  return Native.enroll(jwt);
}

export async function zitiStatus(): Promise<string> {
  return Native ? Native.status() : 'unavailable';
}

export async function zitiServiceAvailable(name: string): Promise<boolean> {
  return Native ? Native.serviceAvailable(name) : false;
}

export async function zitiDial(name: string): Promise<string> {
  if (!Native) throw new Error('OpenZiti native module not installed in this build');
  return Native.dial(name);
}
