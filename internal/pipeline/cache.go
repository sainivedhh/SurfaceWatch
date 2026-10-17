// Package pipeline provides Redis caching with resilient fallback.
// CACHE STRATEGY:
// 1. Hot reads (Finding lookups and recent fingerprints) are cached in Redis with a TTL (default 15m).
// 2. Write-Through Invalidation: On finding update or status transition, cache keys are deleted.
// 3. Graceful Degradation: If Redis fails, errors are logged as warnings and the system
//    falls back to PostgreSQL without failing user requests.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache defines the key-value caching interface.
type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	IsAvailable() bool
}

// MemoryCache provides an in-memory fallback for local offline testing.
type MemoryCache struct {
	mu    sync.RWMutex
	store map[string]entry
}

type entry struct {
	val       string
	expiresAt time.Time
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{store: make(map[string]entry)}
}

func (m *MemoryCache) Get(ctx context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.store[key]
	if !ok || time.Now().After(e.expiresAt) {
		return "", fmt.Errorf("cache miss")
	}
	return e.val, nil
}

func (m *MemoryCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[key] = entry{
		val:       value,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (m *MemoryCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, key)
	return nil
}

func (m *MemoryCache) IsAvailable() bool { return true }

// RedisCache wraps go-redis with fault tolerance.
type RedisCache struct {
	client *redis.Client
	logger *slog.Logger
}

func NewRedisCache(client *redis.Client, logger *slog.Logger) *RedisCache {
	if logger == nil {
		logger = slog.Default()
	}
	return &RedisCache{client: client, logger: logger}
}

func (r *RedisCache) Get(ctx context.Context, key string) (string, error) {
	if r.client == nil {
		return "", fmt.Errorf("redis not configured")
	}
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err != redis.Nil {
			r.logger.Warn("Redis GET error (falling back to database)", "key", key, "error", err)
		}
		return "", err
	}
	return val, nil
}

func (r *RedisCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	if r.client == nil {
		return nil
	}
	if err := r.client.Set(ctx, key, value, ttl).Err(); err != nil {
		r.logger.Warn("Redis SET error (degrading gracefully)", "key", key, "error", err)
		return nil // Don't fail the operation
	}
	return nil
}

func (r *RedisCache) Delete(ctx context.Context, key string) error {
	if r.client == nil {
		return nil
	}
	if err := r.client.Del(ctx, key).Err(); err != nil {
		r.logger.Warn("Redis DEL error (degrading gracefully)", "key", key, "error", err)
		return nil
	}
	return nil
}

func (r *RedisCache) IsAvailable() bool {
	if r.client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	return r.client.Ping(ctx).Err() == nil
}
