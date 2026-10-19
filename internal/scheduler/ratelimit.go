// Package scheduler provides rate limiting per target host.
package scheduler

import (
	"context"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// HostRateLimiter manages isolated token buckets per unique host to prevent
// scanning from causing unintentional denial-of-service on target infrastructure.
type HostRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*entry
	rate     rate.Limit
	burst    int
	ttl      time.Duration
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewHostRateLimiter constructs a token-bucket rate limiter.
// Default: r req/sec, burst allowance.
func NewHostRateLimiter(r rate.Limit, burst int) *HostRateLimiter {
	hrl     := &HostRateLimiter{
		limiters: make(map[string]*entry),
		rate    : r,
		burst   : burst,
		ttl     : 10 * time.Minute,
	}
	return hrl
}

// Wait blocks until the target host's token bucket yields a token or the context cancels.
func (h *HostRateLimiter) Wait(ctx context.Context, target string) error {
	host   := normalizeTarget(target)
	limiter:= h.getLimiter(host)
	return limiter.Wait(ctx)
}

// Allow reports whether an event may happen right now without blocking.
func (h *HostRateLimiter) Allow(target string) bool {
	host   := normalizeTarget(target)
	limiter:= h.getLimiter(host)
	return limiter.Allow()
}

func (h *HostRateLimiter) getLimiter(host string) *rate.Limiter {
	h.mu.Lock()
	defer h.mu.Unlock()

	now     := time.Now()
	e, exists := h.limiters[host]
	if !exists {
		lim     := rate.NewLimiter(h.rate, h.burst)
		h.limiters[host] = &entry{
			limiter : lim,
			lastSeen: now,
		}
		// Periodically clean up stale limiters to prevent memory leaks
		if len(h.limiters) > 1000 {
			h.cleanup(now)
		}
		return lim
	}

	e.lastSeen = now
	return e.limiter
}

func (h *HostRateLimiter) cleanup(now time.Time) {
	for host, e := range h.limiters {
		if now.Sub(e.lastSeen) > h.ttl {
			delete(h.limiters, host)
		}
	}
}

func normalizeTarget(target string) string {
	t:= strings.TrimSpace(strings.ToLower(target))
	if idx := strings.Index(t, "://"); idx != -1 {
		t = t[idx+3:]
	}
	if idx := strings.IndexAny(t, "/?#:"); idx != -1 {
		t = t[:idx]
	}
	return t
}
