import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Stack } from 'expo-router';
import { useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Linking,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import {
  disableTotp,
  enrollTotp,
  setupTotp,
  totpStatus,
  type TotpSetup,
} from '@/features/mfa/totp';

export default function TotpScreen() {
  const qc = useQueryClient();
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [code, setCode] = useState('');

  const status = useQuery({ queryKey: ['totp-status'], queryFn: totpStatus });

  const begin = useMutation({
    mutationFn: setupTotp,
    onSuccess: setSetup,
    onError: (e) => Alert.alert('Error', e instanceof Error ? e.message : String(e)),
  });

  const enroll = useMutation({
    mutationFn: () => enrollTotp(code.trim()),
    onSuccess: () => {
      setSetup(null);
      setCode('');
      qc.invalidateQueries({ queryKey: ['totp-status'] });
      Alert.alert('Enrolled', 'Authenticator app is now set up.');
    },
    onError: (e) =>
      Alert.alert('Invalid code', e instanceof Error ? e.message : String(e)),
  });

  const disable = useMutation({
    mutationFn: disableTotp,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['totp-status'] }),
  });

  const enrolled = status.data?.enrolled;

  return (
    <>
      <Stack.Screen options={{ title: 'Authenticator app' }} />
      <View style={styles.container}>
        {status.isLoading ? (
          <ActivityIndicator style={{ marginTop: 24 }} />
        ) : enrolled && !setup ? (
          <View style={styles.card}>
            <Text style={styles.enrolled}>✓ TOTP is enabled</Text>
            <Pressable
              style={styles.disableBtn}
              onPress={() =>
                Alert.alert('Disable TOTP?', undefined, [
                  { text: 'Cancel', style: 'cancel' },
                  {
                    text: 'Disable',
                    style: 'destructive',
                    onPress: () => disable.mutate(),
                  },
                ])
              }>
              <Text style={styles.disableText}>Disable</Text>
            </Pressable>
          </View>
        ) : setup ? (
          <View style={styles.card}>
            <Text style={styles.label}>1. Add this secret to your authenticator</Text>
            <Text selectable style={styles.secret}>
              {setup.secret}
            </Text>
            {!!setup.provisioning_uri && (
              <Pressable onPress={() => Linking.openURL(setup.provisioning_uri!)}>
                <Text style={styles.link}>Open in authenticator app</Text>
              </Pressable>
            )}
            <Text style={[styles.label, { marginTop: 16 }]}>2. Enter the 6-digit code</Text>
            <TextInput
              style={styles.input}
              value={code}
              onChangeText={setCode}
              keyboardType="number-pad"
              maxLength={6}
              placeholder="000000"
            />
            <Pressable
              style={styles.primary}
              disabled={code.trim().length < 6 || enroll.isPending}
              onPress={() => enroll.mutate()}>
              <Text style={styles.primaryText}>
                {enroll.isPending ? 'Verifying…' : 'Verify & enable'}
              </Text>
            </Pressable>
          </View>
        ) : (
          <Pressable
            style={styles.primary}
            disabled={begin.isPending}
            onPress={() => begin.mutate()}>
            <Text style={styles.primaryText}>
              {begin.isPending ? 'Starting…' : 'Set up authenticator app'}
            </Text>
          </Pressable>
        )}
      </View>
    </>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16, gap: 16 },
  card: { borderRadius: 14, padding: 16, gap: 8, backgroundColor: 'rgba(127,127,127,0.12)' },
  enrolled: { fontSize: 17, fontWeight: '600', color: '#1a8f3c' },
  label: { fontSize: 13, fontWeight: '600', opacity: 0.7 },
  secret: {
    fontFamily: 'monospace',
    fontSize: 18,
    letterSpacing: 1,
    padding: 10,
    backgroundColor: 'rgba(127,127,127,0.15)',
    borderRadius: 8,
  },
  link: { color: '#208AEF', fontWeight: '600', marginTop: 6 },
  input: {
    borderWidth: 1,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 12,
    padding: 12,
    fontSize: 22,
    letterSpacing: 6,
    textAlign: 'center',
  },
  primary: {
    height: 52,
    borderRadius: 14,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 8,
  },
  primaryText: { color: 'white', fontSize: 17, fontWeight: '600' },
  disableBtn: { marginTop: 8 },
  disableText: { color: '#d33', fontWeight: '600' },
});
