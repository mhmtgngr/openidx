import { Stack } from 'expo-router';
import * as LocalAuthentication from 'expo-local-authentication';
import { useCallback, useEffect, useRef, useState } from 'react';
import { AppState, Pressable, StyleSheet, Text, View } from 'react-native';

/**
 * Biometric app-lock: requires Face ID / Touch ID / device passcode when the
 * app is opened or returns to the foreground. No-ops on devices without an
 * enrolled biometric so it never bricks access.
 */
function useAppLock() {
  const [locked, setLocked] = useState(true);
  const [checking, setChecking] = useState(false);
  const enabledRef = useRef<boolean | null>(null);

  const isEnabled = useCallback(async () => {
    if (enabledRef.current === null) {
      const hw = await LocalAuthentication.hasHardwareAsync();
      const enrolled = await LocalAuthentication.isEnrolledAsync();
      enabledRef.current = hw && enrolled;
    }
    return enabledRef.current;
  }, []);

  const unlock = useCallback(async () => {
    if (checking) return;
    setChecking(true);
    try {
      if (!(await isEnabled())) {
        setLocked(false);
        return;
      }
      const r = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Unlock OpenIDX',
      });
      setLocked(!r.success);
    } finally {
      setChecking(false);
    }
  }, [checking, isEnabled]);

  useEffect(() => {
    unlock();
    const sub = AppState.addEventListener('change', (s) => {
      if (s === 'background' || s === 'inactive') setLocked(true);
      else if (s === 'active') unlock();
    });
    return () => sub.remove();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { locked, unlock, checking };
}

export default function AppLayout() {
  const { locked, unlock, checking } = useAppLock();

  if (locked) {
    return (
      <View style={styles.lock}>
        <Text style={styles.lockTitle}>OpenIDX is locked</Text>
        <Pressable style={styles.unlock} onPress={unlock} disabled={checking}>
          <Text style={styles.unlockText}>
            {checking ? 'Authenticating…' : 'Unlock'}
          </Text>
        </Pressable>
      </View>
    );
  }
  return <Stack screenOptions={{ headerShown: true }} />;
}

const styles = StyleSheet.create({
  lock: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 20, padding: 24 },
  lockTitle: { fontSize: 20, fontWeight: '700' },
  unlock: {
    height: 52,
    paddingHorizontal: 40,
    borderRadius: 14,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  unlockText: { color: 'white', fontSize: 17, fontWeight: '600' },
});
