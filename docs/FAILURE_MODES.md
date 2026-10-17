# SurfaceWatch Failure Modes & Resilience Verification

This document catalogs critical failure scenarios, the system's defensive behaviors, and the automated tests in the codebase that verify them.

---

## Failure Modes Summary Matrix

| Failure Scenario | Impact | System Defensive Behavior | Verifying Test |
| :--- | :--- | :--- | :--- |
| **Collector Timeout** | External CT or DNS service hangs | Context deadline expires; collector terminates; job marked failed with transient backoff | `TestFailureMode_CollectorTimeout` |
| **HTTP 429 Rate Limit** | External API throttles collector | Error flagged as transient; honors `Retry-After` header value strictly over base backoff | `TestFailureMode_HTTP429WithRetryAfter` |
| **Worker Crash Mid-Job** | Node killed (OOM, eviction) | Lease expires after `leased_until`; peer worker recovers job via `SKIP LOCKED` query | `TestFailureMode_WorkerCrashAndLeaseExpiry` |
| **Duplicate Job Execution** | Worker redelivers completed job | Idempotent upsert via SHA-256 fingerprint; increments occurrence count without duplicating row | `TestFailureMode_DuplicateJobExecution` |
| **Redis Outage** | Redis container down or network cut | Graceful fallback to PostgreSQL; warnings logged; zero failed user requests | `TestPipeline_RedisDownGracefulDegradation` |
| **Webhook Endpoint Down** | Webhook receiver unavailable | Exponential backoff retry (3 attempts); moved to `dead_letters` table upon exhaustion | `TestWebhook_HMACSigningAndDeadLetter` |
| **SSRF / DNS Rebinding** | Malicious webhook targets loopback or metadata | Blocked both at initial URL validation and at connect time (`DialContext`) | `TestFailureMode_WebhookPrivateIP` |
| **Out-of-Scope Asset** | Operator requests unauthorized target | Refused immediately with `ErrOutOfScope`; zero network or filesystem calls made | `TestFailureMode_OutOfScopeTargetRefusal` |
| **Oversized Request Body** | Malicious client sends 50MB payload | `MaxBodySize` middleware limits body to 1MB via `http.MaxBytesReader`; returns 400 | `TestFailureMode_OversizedRequestBody` |
| **Cursor Pagination Edge Cases**| Client requests out-of-bounds offset | Returns empty slice and empty cursor; no out-of-index panics or errors | `TestFailureMode_CursorPaginationEdgeCases` |
| **Cross-Tenant IDOR Attempt** | Tenant A attempts to view Tenant B finding | Scoped lookup by `tenant_id` returns 404 Not Found (no information disclosure) | `TestAPI_TenantIsolation_IDORDefense` |

---

## Detailed Failure Analysis

### 1. Worker Crash & Lease Recovery
- **Failure**: A worker process claims a scan job from the queue and crashes (e.g., segfault or SIGKILL) before marking completion or error.
- **Handling**: The database record maintains a `leased_until` timestamp. Active workers extend this lease every 10 seconds via a background heartbeat goroutine. When the crashing worker stops heartbeating, `leased_until < NOW()` becomes true. Another worker querying with `SKIP LOCKED` claims the expired job, increments `attempts`, and resumes processing.
- **Proof**: `internal/failure_test.go:TestFailureMode_WorkerCrashAndLeaseExpiry`.

### 2. SSRF & DNS Rebinding at Connect Time
- **Failure**: An attacker registers a webhook pointing to a domain they control. At registration time, the domain resolves to a public IP (`203.0.113.1`). But during actual webhook dispatch, the DNS server changes the record to `169.254.169.254` (AWS metadata) or `127.0.0.1` (local loopback).
- **Handling**: Standard URL validation at registration time is insufficient. SurfaceWatch injects a custom `SafeDialContext` into `http.Transport`. When the socket connection is initiated, it resolves the IP, verifies that no resolved address falls within `restrictedCIDRs`, and pins the socket connection directly to that validated IP. If any restricted address is detected, the dialer aborts with `ErrSSRFBlocked`.
- **Proof**: `internal/failure_test.go:TestFailureMode_WebhookPrivateIP` and `internal/api/api_test.go:TestSSRFProtection`.

### 3. Redis Outage & Graceful Degradation
- **Failure**: Redis is killed or unreachable during finding ingestion or lookup.
- **Handling**: All cache interactions are wrapped in the `Cache` interface. When `client.Get()` or `client.Set()` returns a network connection error, the error is logged as a structured warning, and execution continues directly against PostgreSQL. The API never returns a 500 status due to cache unavailability.
- **Proof**: `internal/pipeline/pipeline_test.go:TestPipeline_RedisDownGracefulDegradation`.

### 4. Idempotent Deduplication
- **Failure**: Network latency or queue redelivery causes a scan job to run twice or findings from consecutive scans to overlap.
- **Handling**: Every finding is hashed via `GenerateFingerprint(findingType, assetValue, evidenceKey)`. The database checks `(tenant_id, fingerprint)`. If already present, it updates `last_seen` and increments `occurrence_count`. If a finding was previously marked `resolved` by an analyst and reappears, it transitions automatically to `reopened`.
- **Proof**: `internal/failure_test.go:TestFailureMode_DuplicateJobExecution` and `internal/pipeline/pipeline_test.go:TestPipeline_UpsertAndReopen`.
