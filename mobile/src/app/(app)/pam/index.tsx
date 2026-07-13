import { useQuery } from '@tanstack/react-query';
import { Link, Stack } from 'expo-router';
import { useState } from 'react';
import {
  ActivityIndicator,
  FlatList,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import { listEntries, type PamEntry } from '@/features/pam/api';

const PROTO_ICON: Record<string, string> = {
  ssh: '⌘',
  rdp: '🖥',
  vnc: '🖥',
  telnet: '⌨',
  website: '🌐',
};

export default function PamListScreen() {
  const [q, setQ] = useState('');
  const { data, isLoading, refetch, isRefetching } = useQuery({
    queryKey: ['pam-entries'],
    queryFn: () => listEntries(),
  });

  const entries = (data ?? []).filter(
    (e) => e.entry_type !== 'folder' && e.name.toLowerCase().includes(q.toLowerCase()),
  );

  return (
    <>
      <Stack.Screen options={{ title: 'Connections' }} />
      <View style={styles.searchWrap}>
        <TextInput
          style={styles.search}
          placeholder="Search connections…"
          value={q}
          onChangeText={setQ}
          autoCapitalize="none"
        />
      </View>
      {isLoading ? (
        <ActivityIndicator style={{ marginTop: 32 }} />
      ) : (
        <FlatList<PamEntry>
          data={entries}
          keyExtractor={(e) => e.id}
          onRefresh={refetch}
          refreshing={isRefetching}
          contentContainerStyle={{ padding: 16 }}
          ListEmptyComponent={<Text style={styles.hint}>No connections available.</Text>}
          renderItem={({ item }) => (
            <Link href={`/(app)/pam/${item.id}`} asChild>
              <View style={styles.row}>
                <Text style={styles.icon}>{PROTO_ICON[item.entry_type] ?? '•'}</Text>
                <View style={{ flex: 1 }}>
                  <Text style={styles.name} numberOfLines={1}>
                    {item.name}
                  </Text>
                  <Text style={styles.meta}>
                    {item.entry_type}
                    {item.hostname ? ` · ${item.hostname}` : ''}
                    {item.require_approval ? ' · approval' : ''}
                    {item.record_session ? ' · recorded' : ''}
                  </Text>
                </View>
                <Text style={styles.chevron}>›</Text>
              </View>
            </Link>
          )}
        />
      )}
    </>
  );
}

const styles = StyleSheet.create({
  searchWrap: { padding: 12 },
  search: {
    borderWidth: 1,
    borderColor: 'rgba(127,127,127,0.4)',
    borderRadius: 12,
    paddingHorizontal: 14,
    height: 44,
  },
  hint: { opacity: 0.6, textAlign: 'center', marginTop: 40 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingVertical: 14,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: 'rgba(127,127,127,0.25)',
  },
  icon: { fontSize: 22, width: 28, textAlign: 'center' },
  name: { fontSize: 16, fontWeight: '600' },
  meta: { fontSize: 13, opacity: 0.6, marginTop: 2 },
  chevron: { fontSize: 22, opacity: 0.4 },
});
