import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Stack } from 'expo-router';
import {
  ActivityIndicator,
  Alert,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import {
  enrollDevice,
  getAgentIdentity,
  getZitiJwt,
  reportPosture,
} from '@/features/ziti/device';
import { zitiAvailable, zitiEnroll, zitiStatus } from '@/features/ziti/native';
import { collectPosture, type PostureResult } from '@/features/ziti/posture';

export default function DeviceScreen() {
  const qc = useQueryClient();

  const identity = useQuery({ queryKey: ['agent-identity'], queryFn: getAgentIdentity });
  const posture = useQuery({ queryKey: ['posture'], queryFn: collectPosture });
  const ziti = useQuery({ queryKey: ['ziti-status'], queryFn: zitiStatus });

  const enroll = useMutation({
    mutationFn: async () => {
      await enrollDevice();
      // If the native Ziti module is present, enroll the overlay identity too.
      if (zitiAvailable()) {
        const jwt = await getZitiJwt();
        if (jwt) await zitiEnroll(jwt);
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-identity'] });
      qc.invalidateQueries({ queryKey: ['ziti-status'] });
      Alert.alert('Enrolled', 'This device is now managed by OpenIDX.');
    },
    onError: (e) => Alert.alert('Enroll failed', e instanceof Error ? e.message : String(e)),
  });

  const report = useMutation({
    mutationFn: async () => reportPosture(await collectPosture()),
    onSuccess: (ok) =>
      Alert.alert(ok ? 'Posture reported' : 'Enroll first', ok ? '' : 'Enroll this device before reporting posture.'),
    onError: (e) => Alert.alert('Report failed', e instanceof Error ? e.message : String(e)),
  });

  const enrolled = !!identity.data;

  return (
    <>
      <Stack.Screen options={{ title: 'This device' }} />
      <ScrollView contentContainerStyle={styles.container}>
        <View style={styles.card}>
          <Text style={styles.status}>
            {enrolled ? '✓ Enrolled & managed' : 'Not enrolled'}
          </Text>
          {enrolled && (
            <Text style={styles.mono}>agent: {identity.data!.agentId}</Text>
          )}
          <Text style={styles.mono}>
            OpenZiti: {ziti.data ?? '…'}{!zitiAvailable() ? ' (native module not in this build)' : ''}
          </Text>
        </View>

        {!enrolled && (
          <Pressable
            style={styles.primary}
            disabled={enroll.isPending}
            onPress={() => enroll.mutate()}>
            <Text style={styles.primaryText}>
              {enroll.isPending ? 'Enrolling…' : 'Enroll this device'}
            </Text>
          </Pressable>
        )}

        <Text style={styles.section}>Posture</Text>
        {posture.isLoading ? (
          <ActivityIndicator />
        ) : (
          (posture.data ?? []).map((p: PostureResult) => (
            <View key={p.check_type} style={styles.row}>
              <Text style={styles.dot}>
                {p.result.status === 'pass' ? '🟢' : p.result.status === 'fail' ? '🔴' : '⚪'}
              </Text>
              <Text style={styles.rowText}>{p.result.message}</Text>
            </View>
          ))
        )}

        <Pressable
          style={[styles.secondary, !enrolled && styles.disabled]}
          disabled={!enrolled || report.isPending}
          onPress={() => report.mutate()}>
          <Text style={styles.secondaryText}>
            {report.isPending ? 'Reporting…' : 'Report posture now'}
          </Text>
        </Pressable>
      </ScrollView>
    </>
  );
}

const styles = StyleSheet.create({
  container: { padding: 16, gap: 12 },
  card: { borderRadius: 14, padding: 16, gap: 6, backgroundColor: 'rgba(127,127,127,0.12)' },
  status: { fontSize: 17, fontWeight: '700' },
  mono: { fontFamily: 'monospace', fontSize: 12, opacity: 0.7 },
  primary: {
    height: 52,
    borderRadius: 14,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  primaryText: { color: 'white', fontSize: 17, fontWeight: '700' },
  section: { fontSize: 12, fontWeight: '700', textTransform: 'uppercase', opacity: 0.5, marginTop: 8 },
  row: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingVertical: 6 },
  dot: { fontSize: 14 },
  rowText: { fontSize: 15, flex: 1 },
  secondary: {
    height: 48,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: 'rgba(127,127,127,0.5)',
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 8,
  },
  disabled: { opacity: 0.4 },
  secondaryText: { fontSize: 16, fontWeight: '600' },
});
