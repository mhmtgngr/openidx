import { Link, Stack } from 'expo-router';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { useAuth } from '@/lib/auth';

export default function HomeScreen() {
  const { claims, logout } = useAuth();
  const name = claims?.name ?? claims?.preferred_username ?? claims?.email ?? 'there';

  return (
    <>
      <Stack.Screen options={{ title: 'OpenIDX' }} />
      <ScrollView contentContainerStyle={styles.container}>
        <Text style={styles.greeting}>Hi, {name}</Text>
        <Text style={styles.sub}>You are signed in.</Text>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Signed-in identity</Text>
          <Text style={styles.mono}>sub: {claims?.sub ?? '—'}</Text>
          <Text style={styles.mono}>email: {claims?.email ?? '—'}</Text>
          <Text style={styles.mono}>
            roles: {(claims?.roles ?? []).join(', ') || '—'}
          </Text>
        </View>

        <View style={styles.nav}>
          <Link href="/(app)/approvals" asChild>
            <Pressable style={styles.navItem}>
              <Text style={styles.navText}>Approvals</Text>
              <Text style={styles.navChevron}>›</Text>
            </Pressable>
          </Link>
          <Link href="/(app)/security/passkeys" asChild>
            <Pressable style={styles.navItem}>
              <Text style={styles.navText}>Passkeys</Text>
              <Text style={styles.navChevron}>›</Text>
            </Pressable>
          </Link>
        </View>

        <Pressable style={styles.logout} onPress={logout}>
          <Text style={styles.logoutText}>Sign out</Text>
        </Pressable>
      </ScrollView>
    </>
  );
}

const styles = StyleSheet.create({
  container: { padding: 24, gap: 16 },
  greeting: { fontSize: 28, fontWeight: '700' },
  sub: { fontSize: 15, opacity: 0.6 },
  card: {
    borderRadius: 14,
    padding: 16,
    gap: 6,
    backgroundColor: 'rgba(127,127,127,0.12)',
  },
  cardTitle: { fontSize: 16, fontWeight: '600', marginBottom: 4 },
  mono: { fontFamily: 'monospace', fontSize: 13, opacity: 0.8 },
  nav: { marginTop: 8, borderRadius: 14, overflow: 'hidden', backgroundColor: 'rgba(127,127,127,0.12)' },
  navItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 16,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: 'rgba(127,127,127,0.25)',
  },
  navText: { fontSize: 16, fontWeight: '500' },
  navChevron: { fontSize: 22, opacity: 0.4 },
  logout: {
    height: 48,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: '#d33',
    marginTop: 8,
  },
  logoutText: { color: '#d33', fontSize: 16, fontWeight: '600' },
});
