import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Stack, useLocalSearchParams, useRouter } from 'expo-router';
import * as Linking from 'expo-linking';
import { useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import {
  ApprovalRequiredError,
  connect,
  listEntries,
  requestAccess,
  type PamEntry,
} from '@/features/pam/api';

export default function PamDetailScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const router = useRouter();
  const qc = useQueryClient();
  const [reason, setReason] = useState('');
  const [requesting, setRequesting] = useState(false);

  const { data: entry, isLoading } = useQuery({
    queryKey: ['pam-entries'],
    queryFn: () => listEntries(),
    select: (list) => list.find((e) => e.id === id) as PamEntry | undefined,
  });

  const launch = useMutation({
    mutationFn: () => connect(id),
    onSuccess: (res) => {
      if (res.launch_type === 'guacamole' && res.connect_url) {
        router.push({
          pathname: '/(app)/pam/session/[id]',
          params: { id, url: res.connect_url, sessionId: res.session_id ?? '' },
        });
      } else if (res.url) {
        Linking.openURL(res.url);
      } else {
        Alert.alert('Nothing to launch');
      }
    },
    onError: (e) => {
      if (e instanceof ApprovalRequiredError) {
        setRequesting(true);
      } else {
        Alert.alert('Connect failed', e instanceof Error ? e.message : String(e));
      }
    },
  });

  const request = useMutation({
    mutationFn: () => requestAccess(id, reason.trim() || 'Requested from mobile'),
    onSuccess: () => {
      setRequesting(false);
      setReason('');
      qc.invalidateQueries({ queryKey: ['pam-entry-requests'] });
      Alert.alert('Requested', 'Your access request was submitted.');
    },
    onError: (e) =>
      Alert.alert('Request failed', e instanceof Error ? e.message : String(e)),
  });

  if (isLoading) return <ActivityIndicator style={{ marginTop: 40 }} />;
  if (!entry) return <Text style={styles.hint}>Connection not found.</Text>;

  return (
    <>
      <Stack.Screen options={{ title: entry.name }} />
      <ScrollView contentContainerStyle={styles.container}>
        <Text style={styles.name}>{entry.name}</Text>
        <Text style={styles.meta}>
          {entry.entry_type}
          {entry.hostname ? ` · ${entry.hostname}${entry.port ? `:${entry.port}` : ''}` : ''}
        </Text>

        <View style={styles.flags}>
          {entry.require_approval && <Text style={styles.flag}>Approval required</Text>}
          {entry.record_session && <Text style={styles.flag}>Recorded</Text>}
          {entry.reach_mode === 'ziti' && <Text style={styles.flag}>OpenZiti</Text>}
        </View>

        <Pressable
          style={styles.primary}
          disabled={launch.isPending}
          onPress={() => launch.mutate()}>
          <Text style={styles.primaryText}>
            {launch.isPending ? 'Connecting…' : 'Connect'}
          </Text>
        </Pressable>

        {requesting && (
          <View style={styles.reqCard}>
            <Text style={styles.reqTitle}>This connection needs approval</Text>
            <TextInput
              style={styles.input}
              placeholder="Reason (optional)"
              value={reason}
              onChangeText={setReason}
            />
            <Pressable
              style={styles.secondary}
              disabled={request.isPending}
              onPress={() => request.mutate()}>
              <Text style={styles.secondaryText}>
                {request.isPending ? 'Requesting…' : 'Request access'}
              </Text>
            </Pressable>
          </View>
        )}
      </ScrollView>
    </>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, gap: 10 },
  hint: { opacity: 0.6, textAlign: 'center', marginTop: 40 },
  name: { fontSize: 24, fontWeight: '800' },
  meta: { fontSize: 14, opacity: 0.6 },
  flags: { flexDirection: 'row', flexWrap: 'wrap', gap: 8, marginVertical: 8 },
  flag: {
    fontSize: 12,
    fontWeight: '700',
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 999,
    backgroundColor: 'rgba(127,127,127,0.18)',
    overflow: 'hidden',
  },
  primary: {
    height: 52,
    borderRadius: 14,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 8,
  },
  primaryText: { color: 'white', fontSize: 17, fontWeight: '700' },
  reqCard: {
    marginTop: 16,
    padding: 16,
    borderRadius: 14,
    backgroundColor: 'rgba(201,138,0,0.12)',
    gap: 10,
  },
  reqTitle: { fontWeight: '700' },
  input: {
    borderWidth: 1,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 12,
    padding: 12,
  },
  secondary: {
    height: 48,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: '#c98a00',
    alignItems: 'center',
    justifyContent: 'center',
  },
  secondaryText: { color: '#c98a00', fontSize: 16, fontWeight: '700' },
});
