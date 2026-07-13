import { Stack, useLocalSearchParams } from 'expo-router';
import { useEffect } from 'react';
import { ActivityIndicator, StyleSheet, Text, View } from 'react-native';
import { WebView } from 'react-native-webview';

import { endSession } from '@/features/pam/api';

/**
 * Renders a brokered Guacamole session in a WebView pointed at the
 * browser-facing connect URL (GUACAMOLE_PUBLIC_URL-based). SSH/RDP/VNC are
 * rendered by the Guacamole web client; the injected credential never reaches
 * the app. Best-effort session-end bookkeeping on unmount.
 */
export default function PamSessionScreen() {
  const { url, sessionId } = useLocalSearchParams<{
    url: string;
    sessionId?: string;
  }>();

  useEffect(() => {
    return () => {
      if (sessionId) endSession(sessionId).catch(() => {});
    };
  }, [sessionId]);

  if (!url) {
    return <Text style={styles.hint}>No session URL.</Text>;
  }

  return (
    <>
      <Stack.Screen options={{ title: 'Session' }} />
      <WebView
        source={{ uri: url }}
        style={styles.web}
        startInLoadingState
        renderLoading={() => (
          <View style={styles.loading}>
            <ActivityIndicator size="large" />
          </View>
        )}
        // Guacamole uses a websocket tunnel; keep media/JS enabled.
        javaScriptEnabled
        domStorageEnabled
        mediaPlaybackRequiresUserAction={false}
      />
    </>
  );
}

const styles = StyleSheet.create({
  web: { flex: 1 },
  hint: { opacity: 0.6, textAlign: 'center', marginTop: 40 },
  loading: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
