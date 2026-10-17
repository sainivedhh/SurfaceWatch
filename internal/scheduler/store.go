// Package scheduler provides robust, fault-tolerant job dispatching for SurfaceWatch.
// It features distributed leasing via PostgreSQL SKIP LOCKED, worker heartbeating,
// per-host token bucket rate limiting, jittered exponential backoff, circuit breaking,
// and graceful worker pool shutdown.
package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/model"
)

// JobStatus represents the state of a scan task in the queue.
type JobStatus string

const (
	JobStatusQueued    JobStatus = "queued"
	JobStatusLeased    JobStatus = "leased"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
)

// Job represents an atomic unit of work to be performed by a collector against a target asset.
type Job struct {
	ID            uuid.UUID   `json:"id"`
	TenantID      string      `json:"tenant_id"`
	ScanID        uuid.UUID   `json:"scan_id"`
	CollectorName string      `json:"collector_name"`
	Target        model.Asset `json:"target"`
	Status        JobStatus   `json:"status"`
	WorkerID      string      `json:"worker_id,omitempty"`
	LeasedUntil   *time.Time  `json:"leased_until,omitempty"`
	Attempts      int         `json:"attempts"`
	MaxAttempts   int         `json:"max_attempts"`
	LastError     string      `json:"last_error,omitempty"`
	NextRunAt     time.Time   `json:"next_run_at"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// Store defines the interface for job queuing and distributed leasing.
type Store interface {
	Enqueue(ctx context.Context, job *Job) error
	// ClaimJobs atomically leases available jobs using SELECT ... FOR UPDATE SKIP LOCKED semantics.
	ClaimJobs(ctx context.Context, workerID string, limit int, leaseDuration time.Duration) ([]*Job, error)
	// Heartbeat extends the lease of an actively running job to prevent orphan reassignment.
	Heartbeat(ctx context.Context, jobID uuid.UUID, workerID string, extendBy time.Duration) error
	// Complete marks a job as successfully finished.
	Complete(ctx context.Context, jobID uuid.UUID, workerID string) error
	// Fail marks a job failure and schedules a retry if attempts < max_attempts.
	Fail(ctx context.Context, jobID uuid.UUID, workerID string, errMsg string, backoff time.Duration, canRetry bool) error
}

var (
	ErrJobNotFound = errors.New("job not found")
	ErrLeaseLost   = errors.New("job lease lost or held by another worker")
)

// MemoryStore provides a thread-safe, in-memory implementation of the distributed leasing
// semantics (SELECT ... FOR UPDATE SKIP LOCKED) for ultra-fast, offline testing.
type MemoryStore struct {
	mu   sync.Mutex
	jobs map[uuid.UUID]*Job
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		jobs: make(map[uuid.UUID]*Job),
	}
}

func (s *MemoryStore) Enqueue(ctx context.Context, job *Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}
	job.Status = JobStatusQueued
	job.CreatedAt = now
	job.UpdatedAt = now
	if job.NextRunAt.IsZero() {
		job.NextRunAt = now
	}
	if job.MaxAttempts == 0 {
		job.MaxAttempts = 3
	}

	cpy := *job
	s.jobs[job.ID] = &cpy
	return nil
}

// ClaimJobs simulates PostgreSQL SELECT ... FOR UPDATE SKIP LOCKED:
// It claims jobs that are queued OR whose lease has expired, skipping any
// jobs that are actively leased by healthy workers.
func (s *MemoryStore) ClaimJobs(ctx context.Context, workerID string, limit int, leaseDuration time.Duration) ([]*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var claimed []*Job

	for _, job := range s.jobs {
		if len(claimed) >= limit {
			break
		}

		if job.Status == JobStatusCompleted {
			continue
		}

		// A job can be claimed if:
		// 1. It is queued AND ready (NextRunAt <= now)
		// 2. OR it was leased, but its lease expired (worker died/timed out) AND attempts < max_attempts
		isReadyQueued := job.Status == JobStatusQueued && (job.NextRunAt.Before(now) || job.NextRunAt.Equal(now))
		isLeaseExpired := job.Status == JobStatusLeased && job.LeasedUntil != nil && job.LeasedUntil.Before(now) && job.Attempts < job.MaxAttempts

		if isReadyQueued || isLeaseExpired {
			leaseExpires := now.Add(leaseDuration)
			job.Status = JobStatusLeased
			job.WorkerID = workerID
			job.LeasedUntil = &leaseExpires
			job.Attempts++
			job.UpdatedAt = now

			cpy := *job
			claimed = append(claimed, &cpy)
		}
	}

	return claimed, nil
}

func (s *MemoryStore) Heartbeat(ctx context.Context, jobID uuid.UUID, workerID string, extendBy time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, exists := s.jobs[jobID]
	if !exists {
		return ErrJobNotFound
	}

	// Verify the worker still holds the lease
	if job.WorkerID != workerID || job.Status != JobStatusLeased {
		return ErrLeaseLost
	}

	now := time.Now().UTC()
	newLease := now.Add(extendBy)
	job.LeasedUntil = &newLease
	job.UpdatedAt = now
	return nil
}

func (s *MemoryStore) Complete(ctx context.Context, jobID uuid.UUID, workerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, exists := s.jobs[jobID]
	if !exists {
		return ErrJobNotFound
	}

	if job.WorkerID != workerID {
		return ErrLeaseLost
	}

	now := time.Now().UTC()
	job.Status = JobStatusCompleted
	job.LeasedUntil = nil
	job.UpdatedAt = now
	return nil
}

func (s *MemoryStore) Fail(ctx context.Context, jobID uuid.UUID, workerID string, errMsg string, backoff time.Duration, canRetry bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, exists := s.jobs[jobID]
	if !exists {
		return ErrJobNotFound
	}

	if job.WorkerID != workerID {
		return ErrLeaseLost
	}

	now := time.Now().UTC()
	job.LastError = errMsg
	job.UpdatedAt = now
	job.LeasedUntil = nil

	if canRetry && job.Attempts < job.MaxAttempts {
		job.Status = JobStatusQueued
		job.NextRunAt = now.Add(backoff)
	} else {
		job.Status = JobStatusFailed
	}

	return nil
}

// SQL schema for PostgreSQL SKIP LOCKED leasing
const PostgresJobsSchema = `
CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    scan_id UUID NOT NULL,
    collector_name VARCHAR(64) NOT NULL,
    target_asset JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    worker_id VARCHAR(128),
    leased_until TIMESTAMPTZ,
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    last_error TEXT,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_jobs_claim ON jobs (status, next_run_at) 
WHERE status = 'queued';

CREATE INDEX IF NOT EXISTS idx_jobs_lease_expiry ON jobs (status, leased_until) 
WHERE status = 'leased';
`

// ClaimJobsSQL is the production PostgreSQL query using SKIP LOCKED
const ClaimJobsSQL = `
WITH available_jobs AS (
    SELECT id
    FROM jobs
    WHERE (status = 'queued' AND next_run_at <= NOW())
       OR (status = 'leased' AND leased_until < NOW() AND attempts < max_attempts)
    ORDER BY next_run_at ASC
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
UPDATE jobs
SET status = 'leased',
    worker_id = $2,
    leased_until = NOW() + $3::interval,
    attempts = attempts + 1,
    updated_at = NOW()
FROM available_jobs
WHERE jobs.id = available_jobs.id
RETURNING jobs.id, jobs.tenant_id, jobs.scan_id, jobs.collector_name, 
          jobs.target_asset, jobs.status, jobs.worker_id, jobs.leased_until, 
          jobs.attempts, jobs.max_attempts, jobs.last_error, jobs.next_run_at, 
          jobs.created_at, jobs.updated_at;
`
