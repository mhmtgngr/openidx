import { useQuery } from '@tanstack/react-query';
import { Stack } from 'expo-router';
import { ActivityIndicator, ScrollView, StyleSheet, Text, View } from 'react-native';

import type { AccessRequest } from '@/features/approvals/api';
import { listMyRequests } from '@/features/myaccess/api';
import { useAuth } from '@/lib/auth';

const STATUS_COLOR: Record<string, string> = {
  pending: '#c98a00',
  approved: '#1a8f3c',
  fulfilled: '#1a8f3c',
  denied: '#d33',
  cancelled: '#888',
};

export default function MyAccessScreen() {
  const { claims } = useAuth();
  const { data, isLoading } = useQuery({
    queryKey: ['my-requests'],
    queryFn: listMyRequests,
  });

  const chips = (label: string, items?: string[]) =>
    !!items?.length && (
      <View style={styles.section}>
        <Text style={styles.label}>{label}</Text>
        <View style={styles.chips}>
          {items.map((r) => (
            <Text key={r} style={styles.chip}>
              {r}
            </Text>
          ))}
        </View>
      </View>
    );

  return (
    <>
      <Stack.Screen options={{ title: 'My Access' }} />
      <ScrollView contentContainerStyle={styles.container}>
        {chips('Roles', claims?.roles)}
        {chips('Groups', claims?.groups)}

        <Text style={[styles.label, { marginTop: 8 }]}>My requests</Text>
        {isLoading ? (
          <ActivityIndicator style={{ marginTop: 16 }} />
        ) : (data ?? []).length === 0 ? (
          <Text style={styles.hint}>No access requests.</Text>
        ) : (
          (data as AccessRequest[]).map((r) => (
            <View key={r.id} style={styles.card}>
              <View style={styles.rowTop}>
                <Text style={styles.resource} numberOfLines={1}>
                  {r.resource_name}
                </Text>
                <Text style={[styles.status, { color: STATUS_COLOR[r.status] ?? '#888' }]}>
                  {r.status}
                </Text>
              </View>
              <Text style={styles.meta}>
                {r.resource_type}
                {r.expires_at
                  ? ` · expires ${new Date(r.expires_at).toLocaleDateString()}`
                  : ''}
              </Text>
            </View>
          ))
        )}
      </ScrollView>
    </>
  );
}

const styles = StyleSheet.create({
  container: { padding: 16, gap: 10 },
  section: { gap: 6 },
  label: { fontSize: 12, fontWeight: '700', textTransform: 'uppercase', opacity: 0.5 },
  chips: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  chip: {
    fontSize: 13,
    fontWeight: '600',
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 999,
    backgroundColor: 'rgba(32,138,239,0.15)',
    color: '#208AEF',
    overflow: 'hidden',
  },
  hint: { opacity: 0.6, marginTop: 12 },
  card: {
    borderRadius: 12,
    padding: 14,
    backgroundColor: 'rgba(127,127,127,0.12)',
    gap: 4,
  },
  rowTop: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  resource: { fontSize: 16, fontWeight: '700', flex: 1 },
  status: { fontSize: 12, fontWeight: '700', textTransform: 'uppercase' },
  meta: { fontSize: 13, opacity: 0.6 },
});
