import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Stack } from 'expo-router';
import {
  ActivityIndicator,
  Alert,
  FlatList,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import {
  deletePasskey,
  enrollPasskey,
  listPasskeys,
  passkeysSupported,
  type PasskeyCredential,
} from '@/features/mfa/passkey';

export default function PasskeysScreen() {
  const qc = useQueryClient();
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['passkeys'],
    queryFn: listPasskeys,
  });

  const enroll = useMutation({
    mutationFn: enrollPasskey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['passkeys'] }),
    onError: (e) =>
      Alert.alert('Enroll failed', e instanceof Error ? e.message : String(e)),
  });

  const remove = useMutation({
    mutationFn: deletePasskey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['passkeys'] }),
    onError: (e) =>
      Alert.alert('Delete failed', e instanceof Error ? e.message : String(e)),
  });

  return (
    <>
      <Stack.Screen options={{ title: 'Passkeys' }} />
      <View style={styles.container}>
        <Pressable
          style={[styles.addBtn, !passkeysSupported() && styles.disabled]}
          disabled={!passkeysSupported() || enroll.isPending}
          onPress={() => enroll.mutate()}>
          <Text style={styles.addText}>
            {enroll.isPending ? 'Creating…' : '+ Add a passkey'}
          </Text>
        </Pressable>
        {!passkeysSupported() && (
          <Text style={styles.hint}>Passkeys aren’t supported on this device.</Text>
        )}

        {isLoading ? (
          <ActivityIndicator style={{ marginTop: 24 }} />
        ) : isError ? (
          <Text style={styles.hint}>Couldn’t load passkeys. Pull to retry.</Text>
        ) : (
          <FlatList<PasskeyCredential>
            data={data ?? []}
            keyExtractor={(c) => c.id}
            onRefresh={refetch}
            refreshing={isLoading}
            ListEmptyComponent={
              <Text style={styles.hint}>No passkeys yet.</Text>
            }
            renderItem={({ item }) => (
              <View style={styles.row}>
                <View style={{ flex: 1 }}>
                  <Text style={styles.mono} numberOfLines={1}>
                    {item.id}
                  </Text>
                  {!!item.created_at && (
                    <Text style={styles.sub}>
                      added {new Date(item.created_at).toLocaleDateString()}
                    </Text>
                  )}
                </View>
                <Pressable onPress={() => remove.mutate(item.id)}>
                  <Text style={styles.del}>Remove</Text>
                </Pressable>
              </View>
            )}
          />
        )}
      </View>
    </>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16, gap: 12 },
  addBtn: {
    height: 50,
    borderRadius: 12,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  disabled: { opacity: 0.4 },
  addText: { color: 'white', fontSize: 16, fontWeight: '600' },
  hint: { opacity: 0.6, textAlign: 'center', marginTop: 16 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 14,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: 'rgba(127,127,127,0.3)',
    gap: 12,
  },
  mono: { fontFamily: 'monospace', fontSize: 13 },
  sub: { fontSize: 12, opacity: 0.5, marginTop: 2 },
  del: { color: '#d33', fontWeight: '600' },
});
