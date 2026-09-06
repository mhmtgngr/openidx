package identity

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// The native client ships no Firebase/APNs SDK, so it registers a synthetic
// `ntfy:<id>` device token and delivery happens over the per-user ntfy topic.
// sendPushNotification must recognise that token and skip the provider hop;
// without the skip, every challenge for every phone would try FCM/APNs with an
// id those services cannot accept.
func TestSendPushNotification_SkipsProviderForNtfyTokens(t *testing.T) {
	// No FCM credentials file, no APNs key: the provider paths cannot succeed,
	// so a nil error can only come from the skip.
	svc := &Service{cfg: &config.Config{}, logger: zap.NewNop()}
	challenge := &PushMFAChallenge{
		ID:            "chal-1",
		ChallengeCode: "42",
		ExpiresAt:     time.Now().Add(time.Minute),
	}

	for _, platform := range []string{"android", "ios", "web"} {
		t.Run(platform, func(t *testing.T) {
			device := &PushMFADevice{
				ID:          "dev-1",
				UserID:      "user-1",
				DeviceToken: "ntfy:0123456789abcdef0123456789abcdef",
				Platform:    platform,
			}
			if err := svc.sendPushNotification(context.Background(), device, challenge); err != nil {
				t.Fatalf("ntfy-transport device should not attempt a provider send: %v", err)
			}
		})
	}
}

// Positive control: the same unconfigured service must still fail for a real
// provider token. If this ever passes, the test above proves nothing — it would
// be green because sending never happens, not because the prefix was honoured.
func TestSendPushNotification_StillAttemptsProviderForRealTokens(t *testing.T) {
	svc := &Service{cfg: &config.Config{}, logger: zap.NewNop()}
	challenge := &PushMFAChallenge{
		ID:            "chal-2",
		ChallengeCode: "42",
		ExpiresAt:     time.Now().Add(time.Minute),
	}
	device := &PushMFADevice{
		ID:          "dev-2",
		UserID:      "user-1",
		DeviceToken: "fMEP0kQ1S3a:APA91bF_real_looking_fcm_token",
		Platform:    "android",
	}

	err := svc.sendPushNotification(context.Background(), device, challenge)
	if err == nil {
		t.Fatal("a provider token on an unconfigured service must report the failure, not succeed silently")
	}
	if !strings.Contains(err.Error(), "FCM not configured") {
		t.Fatalf("expected the FCM-not-configured error, got: %v", err)
	}
}

// The prefix is a contract shared with client/lib/mobile/push_token_service.dart.
// Pinned so a rename on either side is a failing test rather than a silent
// return to "every challenge tries FCM with an id it cannot use".
func TestNtfyDeviceTokenPrefixIsPinned(t *testing.T) {
	if ntfyDeviceTokenPrefix != "ntfy:" {
		t.Fatalf("prefix changed to %q; update client/lib/mobile/push_token_service.dart in the same commit", ntfyDeviceTokenPrefix)
	}
}
