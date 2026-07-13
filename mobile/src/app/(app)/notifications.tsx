import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Stack, useRouter } from 'expo-router';
import {
  ActivityIndicator,
  FlatList,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import {
  listNotifications,
  markAllRead,
  markRead,
  type Notification,
} from '@/features/notifications/api';

export default function NotificationsScreen() {
  const qc = useQueryClient();
  const router = useRouter();
  const { data, isLoading, refetch, isRefetching } = useQuery({
    queryKey: ['notifications'],
    queryFn: () => listNotifications(false),
    refetchInterval: 30000,
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['notifications'] });
    qc.invalidateQueries({ queryKey: ['notifications-unread'] });
  };
  const readOne = useMutation({ mutationFn: (id: string) => markRead([id]), onSuccess: invalidate });
  const readAll = useMutation({ mutationFn: markAllRead, onSuccess: invalidate });

  const open = (n: Notification) => {
    if (!n.read) readOne.mutate(n.id);
    if (n.link) router.push(n.link as never);
  };

  return (
    <>
      <Stack.Screen
        options={{
          title: 'Notifications',
          headerRight: () => (
            <Pressable onPress={() => readAll.mutate()}>
              <Text style={styles.readAll}>Read all</Text>
            </Pressable>
          ),
        }}
      />
      {isLoading ? (
        <ActivityIndicator style={{ marginTop: 32 }} />
      ) : (
        <FlatList<Notification>
          data={data ?? []}
          keyExtractor={(n) => n.id}
          onRefresh={refetch}
          refreshing={isRefetching}
          contentContainerStyle={{ padding: 16 }}
          ListEmptyComponent={<Text style={styles.hint}>No notifications.</Text>}
          renderItem={({ item }) => (
            <Pressable
              style={[styles.row, !item.read && styles.unread]}
              onPress={() => open(item)}>
              <View style={{ flex: 1 }}>
                <Text style={styles.title}>{item.title}</Text>
                {!!item.body && <Text style={styles.body}>{item.body}</Text>}
                <Text style={styles.time}>
                  {new Date(item.created_at).toLocaleString()}
                </Text>
              </View>
              {!item.read && <View style={styles.dot} />}
            </Pressable>
          )}
        />
      )}
    </>
  );
}

const styles = StyleSheet.create({
  hint: { opacity: 0.6, textAlign: 'center', marginTop: 40 },
  readAll: { color: '#208AEF', fontWeight: '600' },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    padding: 14,
    borderRadius: 12,
    marginBottom: 8,
  },
  unread: { backgroundColor: 'rgba(32,138,239,0.10)' },
  title: { fontSize: 16, fontWeight: '600' },
  body: { fontSize: 14, opacity: 0.8, marginTop: 2 },
  time: { fontSize: 12, opacity: 0.5, marginTop: 4 },
  dot: { width: 10, height: 10, borderRadius: 5, backgroundColor: '#208AEF' },
});
