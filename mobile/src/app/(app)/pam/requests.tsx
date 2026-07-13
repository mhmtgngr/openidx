import { useQuery } from '@tanstack/react-query';
import { Stack } from 'expo-router';
import {
  ActivityIndicator,
  FlatList,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import { listMyEntryRequests, type PamEntryRequest } from '@/features/pam/api';

const STATUS_COLOR: Record<string, string> = {
  pending: '#c98a00',
  approved: '#1a8f3c',
  denied: '#d33',
  expired: '#888',
};

function ttl(expiresAt?: string | null): string | null {
  if (!expiresAt) return null;
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (ms <= 0) return 'expired';
  const h = Math.floor(ms / 3.6e6);
  const m = Math.floor((ms % 3.6e6) / 6e4);
  return h > 0 ? `${h}h ${m}m left` : `${m}m left`;
}

export default function PamRequestsScreen() {
  const { data, isLoading, refetch, isRefetching } = useQuery({
    queryKey: ['pam-entry-requests'],
    queryFn: listMyEntryRequests,
    refetchInterval: 20000,
  });

  return (
    <>
      <Stack.Screen options={{ title: 'My PAM requests' }} />
      {isLoading ? (
        <ActivityIndicator style={{ marginTop: 32 }} />
      ) : (
        <FlatList<PamEntryRequest>
          data={data ?? []}
          keyExtractor={(r) => r.id}
          onRefresh={refetch}
          refreshing={isRefetching}
          contentContainerStyle={{ padding: 16 }}
          ListEmptyComponent={<Text style={styles.hint}>No PAM access requests.</Text>}
          renderItem={({ item }) => (
            <View style={styles.card}>
              <View style={styles.rowTop}>
                <Text style={styles.name} numberOfLines={1}>
                  {item.entry_name}
                </Text>
                <Text style={[styles.status, { color: STATUS_COLOR[item.status] ?? '#888' }]}>
                  {item.status}
                </Text>
              </View>
              <Text style={styles.meta}>
                {item.entry_type}
                {item.status === 'approved' && ttl(item.expires_at)
                  ? ` · ${ttl(item.expires_at)}`
                  : ''}
              </Text>
              {!!item.reason && <Text style={styles.reason}>{item.reason}</Text>}
            </View>
          )}
        />
      )}
    </>
  );
}

const styles = StyleSheet.create({
  hint: { opacity: 0.6, textAlign: 'center', marginTop: 40 },
  card: {
    borderRadius: 12,
    padding: 14,
    marginBottom: 10,
    backgroundColor: 'rgba(127,127,127,0.12)',
    gap: 4,
  },
  rowTop: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  name: { fontSize: 16, fontWeight: '700', flex: 1 },
  status: { fontSize: 12, fontWeight: '700', textTransform: 'uppercase' },
  meta: { fontSize: 13, opacity: 0.6 },
  reason: { fontSize: 14, opacity: 0.8, marginTop: 2 },
});
