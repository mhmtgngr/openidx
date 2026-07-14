package opa

import (
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// decisionCache is a small, TTL-bounded in-process cache of OPA allow/deny
// decisions, keyed on the authorization input (subject + roles/groups + tenant +
// resource + method + path). It keeps the same authorization decision from
// re-hitting OPA on every request in a burst, which removes OPA from the hot
// path for the common case while a short TTL keeps decisions fresh enough that a
// policy or role change takes effect within seconds.
//
// Only definitive decisions are cached (never errors), so an OPA outage never
// produces stale "allow"s beyond the TTL of a decision made while it was healthy.
type decisionCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
	maxSize int
}

type cacheEntry struct {
	decision Decision
	expires  time.Time
}

func newDecisionCache(ttl time.Duration, maxSize int) *decisionCache {
	return &decisionCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

func (dc *decisionCache) get(key string) (Decision, bool) {
	dc.mu.RLock()
	e, ok := dc.entries[key]
	dc.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return Decision{}, false
	}
	return e.decision, true
}

func (dc *decisionCache) put(key string, d Decision) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	// Bounded size: when full, purge expired entries; if still full, reset. A
	// coarse reset is fine for a few-second TTL cache and guarantees no unbounded
	// growth without an LRU's bookkeeping.
	if len(dc.entries) >= dc.maxSize {
		now := time.Now()
		for k, e := range dc.entries {
			if now.After(e.expires) {
				delete(dc.entries, k)
			}
		}
		if len(dc.entries) >= dc.maxSize {
			dc.entries = make(map[string]cacheEntry, dc.maxSize)
		}
	}
	dc.entries[key] = cacheEntry{decision: d, expires: time.Now().Add(dc.ttl)}
}

// cacheKey builds a stable key for an authorization input. Roles and groups are
// sorted so ordering doesn't fragment the cache.
func cacheKey(in Input) string {
	roles := append([]string(nil), in.User.Roles...)
	sort.Strings(roles)
	groups := append([]string(nil), in.User.Groups...)
	sort.Strings(groups)

	var b strings.Builder
	b.WriteString(in.User.ID)
	b.WriteByte('|')
	b.WriteString(strconv.FormatBool(in.User.Authenticated))
	b.WriteByte('|')
	b.WriteString(in.User.TenantID)
	b.WriteByte('|')
	b.WriteString(strings.Join(roles, ","))
	b.WriteByte('|')
	b.WriteString(strings.Join(groups, ","))
	b.WriteByte('|')
	b.WriteString(in.Resource.Type)
	b.WriteByte('|')
	b.WriteString(in.Resource.Owner)
	b.WriteByte('|')
	b.WriteString(in.Method)
	b.WriteByte('|')
	b.WriteString(in.Path)

	h := fnv.New64a()
	_, _ = h.Write([]byte(b.String()))
	return strconv.FormatUint(h.Sum64(), 16)
}
