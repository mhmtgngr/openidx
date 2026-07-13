import { useMutation, useQuery } from '@tanstack/react-query';
import { Stack, useLocalSearchParams, useRouter } from 'expo-router';
import { useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import { getChallengeStatus, verifyChallenge } from '@/features/mfa/push';

export default function ApprovePushScreen() {
  const { challengeId } = useLocalSearchParams<{ challengeId: string }>();
  const router = useRouter();
  const [code, setCode] = useState('');

  const status = useQuery({
    queryKey: ['push-challenge', challengeId],
    queryFn: () => getChallengeStatus(challengeId),
    enabled: !!challengeId,
    refetchInterval: 5000,
  });

  const verify = useMutation({
    mutationFn: (approved: boolean) =>
      verifyChallenge(challengeId, code.trim(), approved),
    onSuccess: (_r, approved) => {
      Alert.alert(approved ? 'Approved' : 'Denied');
      router.back();
    },
    onError: (e) =>
      Alert.alert('Failed', e instanceof Error ? e.message : String(e)),
  });

  const st = status.data?.status;
  const settled = st === 'approved' || st === 'denied' || st === 'expired';

  return (
    <>
      <Stack.Screen options={{ title: 'Approve sign-in' }} />
      <View style={styles.container}>
        {status.isLoading ? (
          <ActivityIndicator />
        ) : settled ? (
          <Text style={styles.settled}>This request is {st}.</Text>
        ) : (
          <>
            <Text style={styles.prompt}>
              A sign-in is waiting for your approval.
            </Text>
            <Text style={styles.hint}>
              Enter the number shown on the device you’re signing in on.
            </Text>
            <TextInput
              style={styles.input}
              value={code}
              onChangeText={setCode}
              keyboardType="number-pad"
              maxLength={2}
              placeholder="00"
            />
            <View style={styles.actions}>
              <Pressable
                style={[styles.btn, styles.deny]}
                disabled={verify.isPending}
                onPress={() => verify.mutate(false)}>
                <Text style={styles.denyText}>Deny</Text>
              </Pressable>
              <Pressable
                style={[styles.btn, styles.approve]}
                disabled={verify.isPending || code.trim().length === 0}
                onPress={() => verify.mutate(true)}>
                <Text style={styles.approveText}>Approve</Text>
              </Pressable>
            </View>
          </>
        )}
      </View>
    </>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, gap: 12, justifyContent: 'center' },
  prompt: { fontSize: 20, fontWeight: '700', textAlign: 'center' },
  hint: { fontSize: 15, opacity: 0.6, textAlign: 'center' },
  settled: { fontSize: 18, textAlign: 'center', opacity: 0.7 },
  input: {
    borderWidth: 1,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 14,
    padding: 14,
    fontSize: 34,
    letterSpacing: 8,
    textAlign: 'center',
    marginVertical: 12,
  },
  actions: { flexDirection: 'row', gap: 12 },
  btn: { flex: 1, height: 52, borderRadius: 14, alignItems: 'center', justifyContent: 'center' },
  approve: { backgroundColor: '#1a8f3c' },
  approveText: { color: 'white', fontSize: 17, fontWeight: '700' },
  deny: { borderWidth: 1, borderColor: '#d33' },
  denyText: { color: '#d33', fontSize: 17, fontWeight: '700' },
});
