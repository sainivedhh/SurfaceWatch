# SurfaceWatch System Architecture

## 1. High-Level System Architecture

SurfaceWatch is an enterprise attack-surface management (ASM) platform designed with clean domain boundaries, strict multi-tenancy, and resilient asynchronous worker pools.

```
+---------------------------------------------------------------------------------------+
|                                    Client & Operator                                   |
|   +-----------------------+     +--------------------+     +----------------------+   |
|   | Security Operator     |     | Analyst Webhook    |     | REST API Consumer    |   |
|   | (scope.yaml allowlist)|     | (HMAC Verification)|     | (X-API-Key / Bearer) |   |
|   +-----------------------+     +--------------------+     +----------------------+   |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
|                                   HTTP / REST API                                     |
|  [Recoverer] -> [RequestID] -> [SecurityHeaders] -> [MaxBodySize] -> [RateLimiter]   |
|                                           |                                           |
|       +-----------------------------------+-----------------------------------+       |
|       |                                   |                                   |       |
|   /api/v1/assets                     /api/v1/scans                    /api/v1/findings|
|   (Scope Check)                      (Job Enqueue)                    (Cursor Paged)  |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
|                         Distributed Leasing & Scheduler                               |
|   +-------------------------------------------------------------------------------+   |
|   |  PostgreSQL jobs Table (SELECT ... FOR UPDATE SKIP LOCKED)                    |   |
|   |  - LeasedUntil timestamp + Heartbeat goroutines (every 10s)                   |   |
|   |  - Dead worker recovery (expired leases automatically reassigned)              |   |
|   +-------------------------------------------------------------------------------+   |
|                                           |                                           |
|                                           v                                           |
|   +-------------------------------------------------------------------------------+   |
|   |  Goroutine Worker Pool (Configurable Concurrency N=4)                         |   |
|   |  - Context Cancellation & Graceful Shutdown (sync.WaitGroup)                  |   |
|   |  - Per-Host Token Bucket Rate Limiter (golang.org/x/time/rate)                |   |
|   |  - Exponential Backoff + Full Jitter (Retry-After support)                     |   |
|   |  - Per-Collector Circuit Breakers (Closed -> Open -> Half-Open)               |   |
|   +-------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
|                                  Passive Collectors                                   |
|   +---------------+ +---------------+ +---------------+ +-------------+ +---------+  |
|   | CT Collector  | | DNS Resolver  | | Typosquatting | | TLS/Headers | | Secrets |  |
|   | (crt.sh Logs) | | (CNAME Audit) | | (7 Perm Class)| | (Cert Expiry| | (Regex+ |  |
|   |               | | (Takeover)    | | (Homoglyphs)  | |  Weak TLS)  | | Entropy)|  |
|   +---------------+ +---------------+ +---------------+ +-------------+ +---------+  |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
|                                  Findings Pipeline                                    |
|   +-------------------------------------------------------------------------------+   |
|   | 1. Deterministic Fingerprinter: SHA-256(Type | Asset | EvidenceKey)            |   |
|   | 2. Mathematical Scorer: Min(100, TypeWeight * Exposure * Confidence * 10)     |   |
|   | 3. Resilient Redis Cache (Write-Through Invalidation, Graceful Fallback)      |   |
|   | 4. Idempotent Upsert (first_seen, last_seen, count, auto-reopen if resolved)  |   |
|   | 5. Scan Delta Engine (New, Unchanged, Resolved diff between scans)            |   |
|   | 6. SSRF-Safe Webhook Dispatcher (Connect-time DNS pin, HMAC-SHA256 signature)  |   |
|   +-------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------+
```

---

## 2. Core Components & Lifecycle

### 2.1 Scope Guardrail (`internal/scope`)
- **Authority**: Reads `scope.yaml` loaded at server startup.
- **Enforcement**: Evaluates every target asset (`domain`, `subdomain`, `repo`, `cidr`).
- **Defenses**:
  - Normalizes FQDNs (trailing dot stripping, URL scheme stripping, port stripping).
  - Rejects lookalike domain suffix/prefix attacks (`badexample.com`, `example.com.attacker.com`).
  - Rejects directory traversal paths (`../../etc/shadow`).
  - Rejects unlisted CIDR blocks.

### 2.2 Passive Collectors (`internal/collector`)
Every collector satisfies the unified interface:
```go
type Collector interface {
    Name() string
    Collect(ctx context.Context, target model.Asset) ([]RawFinding, error)
}
```
1. **Certificate Transparency (`ct.go`)**: Queries CT logs (crt.sh API), deduplicates subdomains, validates discovered SANs against scope allowlist.
2. **DNS & Takeover (`dns.go`)**: Resolves A/AAAA records; checks CNAME chains pointing to unclaimed third-party SaaS/Cloud domains (GitHub Pages, S3, Azure, Heroku) returning NXDOMAIN.
3. **Typosquatting (`typosquat.go`)**: Generates 7 classes of brand permutations (omission, repetition, transposition, adjacent keyboard keys, homoglyphs, TLD swaps, hyphenations) and tests whether lookalikes are actively resolving in DNS.
4. **TLS & Headers (`tlsheader.go`)**: Inspects leaf certificate expiration, self-signed certificates, deprecated TLS 1.0/1.1 protocols, and validates required security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options).
5. **Secret Scanner (`secrets.go`)**: Scans local repository files for AWS Access Keys, GitHub PATs, JWTs, PEM Private Keys, and Database credentials, alongside high Shannon entropy analysis with placeholder suppression and Luhn checksum validation. Stores redacted previews only.

### 2.3 Distributed Scheduler (`internal/scheduler`)
- **Job Lifecycle**: `queued` -> `leased` -> `completed` / `failed`.
- **Atomic Leasing**:
  ```sql
  SELECT id FROM jobs
  WHERE (status = 'queued' AND next_run_at <= NOW())
     OR (status = 'leased' AND leased_until < NOW() AND attempts < max_attempts)
  ORDER BY next_run_at ASC
  LIMIT $1
  FOR UPDATE SKIP LOCKED;
  ```
- **Active Heartbeating**: Leased workers run an internal goroutine ticking every `lease_duration / 3` to renew their lease. If a worker process crashes, its lease expires, and peer workers immediately pick up the job without operator intervention.
- **Host Rate Limiting**: Dedicated token buckets per normalized hostname guarantee that scan activity never generates excessive load on target infrastructure.
- **Circuit Breakers**: Consecutive failures against an external service trigger an open circuit, mitigating cascading network blockages.

### 2.4 Findings Pipeline (`internal/pipeline`)
- **Deduplication**: SHA-256 fingerprinting ensures that findings from repetitive scans update occurrence counters and timestamps rather than inserting duplicate records.
- **State Transition Engine**:
  - `new`: Initial observation.
  - `acknowledged`: Analyst reviewed.
  - `resolved`: Remediation confirmed.
  - `reopened`: If a previously `resolved` finding is detected again in a later scan, it automatically transitions to `reopened`.
- **Cache Fallback**: Hot reads are served from Redis with 15m TTL. If Redis is down, calls fall back directly to the relational store with zero client disruption.
