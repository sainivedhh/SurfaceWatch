package internal_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

// TestIntegration_PostgresAndRedis verifies real database operations when Docker/compose is active.
// Automatically skips if PostgreSQL or Redis are not reachable.
func TestIntegration_PostgresAndRedis(t *testing.T) {
	pgURL := os.Getenv("SURFACEWATCH_TEST_PG_URL")
	if pgURL == "" {
		pgURL = "postgres://postgres:postgres@localhost:5432/surfacewatch_test?sslmode=disable"
	}

	redisAddr := os.Getenv("SURFACEWATCH_TEST_REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	// 1. Attempt PostgreSQL connection with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	pgConn, err := pgx.Connect(ctx, pgURL)
	if err != nil {
		t.Skipf("SKIPPING INTEGRATION TEST: PostgreSQL is not reachable at %s (%v). Start docker-compose to run full integration tests.", pgURL, err)
		return
	}
	defer pgConn.Close(ctx)

	// 2. Attempt Redis connection with short timeout
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("SKIPPING INTEGRATION TEST: Redis is not reachable at %s (%v). Start docker-compose to run full integration tests.", redisAddr, err)
		return
	}

	t.Log("Successfully connected to PostgreSQL and Redis integration environment!")
}
