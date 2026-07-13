import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Stack, useLocalSearchParams, useRouter } from 'expo-router';
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
  approveRequest,
  denyRequest,
  getRequest,
} from '@/features/approvals/api';

export default function ApprovalDetailScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const qc = useQueryClient();
  const router = useRouter();
  const [comments, setComments] = useState('');

  const { data, isLoading, isError } = useQuery({
    queryKey: ['approvals', id],
    queryFn: () => getRequest(id),
    enabled: !!id,
  });

  const decide = useMutation({
    mutationFn: (decision: 'approve' | 'deny') =>
      decision === 'approve'
        ? approveRequest(id, comments)
        : denyRequest(id, comments),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['approvals'] });
      router.back();
    },
    onError: (e) =>
      Alert.alert('Failed', e instanceof Error ? e.message : String(e)),
  });

  const confirm = (decision: 'approve' | 'deny') =>
    Alert.alert(
      decision === 'approve' ? 'Approve request?' : 'Deny request?',
      data?.resource_name,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: decision === 'approve' ? 'Approve' : 'Deny',
          style: decision === 'deny' ? 'destructive' : 'default',
          onPress: () => decide.mutate(decision),
        },
      ],
    );

  return (
    <>
      <Stack.Screen options={{ title: 'Request' }} />
      {isLoading ? (
        <ActivityIndicator style={{ marginTop: 32 }} />
      ) : isError || !data ? (
        <Text style={styles.hint}>Couldn’t load the request.</Text>
      ) : (
        <ScrollView contentContainerStyle={styles.container}>
          <Text style={styles.resource}>{data.resource_name}</Text>
          <Text style={styles.meta}>
            {data.resource_type} · requested by {data.requester_name}
          </Text>

          <Section label="Justification">
            <Text style={styles.body}>{data.justification || '—'}</Text>
          </Section>

          {!!data.expires_at && (
            <Section label="Expires">
              <Text style={styles.body}>
                {new Date(data.expires_at).toLocaleString()}
              </Text>
            </Section>
          )}

          {!!data.approvals?.length && (
            <Section label="Approval chain">
              {data.approvals.map((a) => (
                <Text key={a.id} style={styles.chain}>
                  {a.step_order + 1}. {a.approver_name} — {a.decision}
                </Text>
              ))}
            </Section>
          )}

          <TextInput
            style={styles.input}
            placeholder="Comments (optional)"
            value={comments}
            onChangeText={setComments}
            multiline
          />

          <View style={styles.actions}>
            <Pressable
              style={[styles.btn, styles.deny]}
              disabled={decide.isPending}
              onPress={() => confirm('deny')}>
              <Text style={styles.denyText}>Deny</Text>
            </Pressable>
            <Pressable
              style={[styles.btn, styles.approve]}
              disabled={decide.isPending}
              onPress={() => confirm('approve')}>
              <Text style={styles.approveText}>Approve</Text>
            </Pressable>
          </View>
        </ScrollView>
      )}
    </>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <View style={styles.section}>
      <Text style={styles.label}>{label}</Text>
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, gap: 8 },
  hint: { opacity: 0.6, textAlign: 'center', marginTop: 40 },
  resource: { fontSize: 24, fontWeight: '800' },
  meta: { fontSize: 14, opacity: 0.6, marginBottom: 8 },
  section: { marginTop: 12, gap: 4 },
  label: {
    fontSize: 12,
    fontWeight: '700',
    textTransform: 'uppercase',
    opacity: 0.5,
  },
  body: { fontSize: 15 },
  chain: { fontSize: 14, opacity: 0.85 },
  input: {
    borderWidth: 1,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 12,
    padding: 12,
    minHeight: 72,
    marginTop: 16,
    textAlignVertical: 'top',
  },
  actions: { flexDirection: 'row', gap: 12, marginTop: 16 },
  btn: {
    flex: 1,
    height: 52,
    borderRadius: 14,
    alignItems: 'center',
    justifyContent: 'center',
  },
  approve: { backgroundColor: '#1a8f3c' },
  approveText: { color: 'white', fontSize: 17, fontWeight: '700' },
  deny: { borderWidth: 1, borderColor: '#d33' },
  denyText: { color: '#d33', fontSize: 17, fontWeight: '700' },
});
