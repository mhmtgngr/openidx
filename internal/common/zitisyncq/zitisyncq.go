// Package zitisyncq is the on-demand Ziti user-sync request queue shared by
// the oauth service (producer: a BrowZer sign-in) and the access service
// (consumer: the Ziti user-sync poller). Faz B7.6.
//
// It is a Redis set, so a user who signs in many times before the drain is
// queued once, plus a short per-user debounce key so a burst of sign-ins
// does not re-queue a user the poller has just synced. Losing a request is
// harmless: the periodic sweep still picks the user up on its next tick.
package zitisyncq

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// Key is the Redis set holding user IDs awaiting an on-demand sync.
const Key = "ziti:user_sync:pending"

const debouncePrefix = "ziti:user_sync:debounce:"

// Debounce is how long one user's request suppresses another.
const Debounce = 30 * time.Second

// Request queues userID for an on-demand sync. Nil-safe and best-effort.
func Request(ctx context.Context, rc *redis.Client, userID string) {
	if rc == nil || userID == "" {
		return
	}
	ok, err := rc.SetNX(ctx, debouncePrefix+userID, "1", Debounce).Result()
	if err != nil || !ok {
		return
	}
	rc.SAdd(ctx, Key, userID)
}

// Drain pops up to max queued user IDs. Nil-safe.
func Drain(ctx context.Context, rc *redis.Client, max int) []string {
	if rc == nil || max <= 0 {
		return nil
	}
	ids, err := rc.SPopN(ctx, Key, int64(max)).Result()
	if err != nil {
		return nil
	}
	return ids
}
