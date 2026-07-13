import { useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import { passkeysSupported } from '@/features/mfa/passkey';
import { useAuth } from '@/lib/auth';

export default function LoginScreen() {
  const { loginWithBrowser, loginWithPasskey } = useAuth();
  const [busy, setBusy] = useState(false);
  const canPasskey = passkeysSupported();

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      Alert.alert('Sign-in failed', e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>OpenIDX</Text>
      <Text style={styles.subtitle}>Secure access, in your pocket.</Text>

      {busy ? (
        <ActivityIndicator size="large" style={{ marginTop: 32 }} />
      ) : (
        <View style={styles.actions}>
          {canPasskey && (
            <Pressable
              style={[styles.button, styles.primary]}
              onPress={() => run(loginWithPasskey)}>
              <Text style={styles.primaryText}>Sign in with passkey</Text>
            </Pressable>
          )}
          <Pressable
            style={[styles.button, canPasskey ? styles.secondary : styles.primary]}
            onPress={() => run(loginWithBrowser)}>
            <Text style={canPasskey ? styles.secondaryText : styles.primaryText}>
              {canPasskey ? 'Other sign-in options' : 'Sign in'}
            </Text>
          </Pressable>
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
  },
  title: { fontSize: 40, fontWeight: '800', letterSpacing: -1 },
  subtitle: { fontSize: 16, opacity: 0.6, marginTop: 8 },
  actions: { width: '100%', marginTop: 40, gap: 12 },
  button: {
    height: 52,
    borderRadius: 14,
    alignItems: 'center',
    justifyContent: 'center',
  },
  primary: { backgroundColor: '#208AEF' },
  primaryText: { color: 'white', fontSize: 17, fontWeight: '600' },
  secondary: { borderWidth: 1, borderColor: 'rgba(127,127,127,0.5)' },
  secondaryText: { fontSize: 16, fontWeight: '600', opacity: 0.8 },
});

