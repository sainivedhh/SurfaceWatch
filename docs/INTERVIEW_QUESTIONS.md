# 15 Technical Interview Questions & Code-Grounded Answers

Use these questions and answers to articulate the design decisions, concurrency model, and security mechanisms of SurfaceWatch in backend and cybersecurity engineering interviews.

---

### Q1: What happens if a worker crashes mid-job?
**Answer**: 
In SurfaceWatch, jobs are claimed using distributed leasing backed by PostgreSQL. When a worker claims a job, it sets `status = 'leased'`, assigns its `worker_id`, and sets `leased_until = NOW() + 30s`. A healthy worker continuously heartbeats every 10 seconds to extend the lease. If the worker process crashes (OOM, segfault, or container termination), its heartbeat ceases and `leased_until` expires. Other workers querying with `SELECT ... FOR UPDATE SKIP LOCKED` check `WHERE (status = 'leased' AND leased_until < NOW() AND attempts < max_attempts)` and immediately claim the expired job, incrementing `attempts` and resuming execution.
*Code reference*: `internal/scheduler/store.go` and `internal/failure_test.go:TestFailureMode_WorkerCrashAndLeaseExpiry`.

---

### Q2: How do you avoid double processing and duplicate findings?
**Answer**: 
At the pipeline level, every discovered issue is converted into a deterministic SHA-256 fingerprint: `SHA-256(finding_type | asset_value | evidence_key)`. When findings are ingested, the store checks for an existing record with that fingerprint for the tenant. If found, it updates `last_seen` and increments `occurrence_count` without inserting a new row. At the queue level, `SELECT ... FOR UPDATE SKIP LOCKED` guarantees that no two workers can claim the same job concurrently.
*Code reference*: `internal/pipeline/scoring.go` and `internal/pipeline/pipeline.go`.

---

### Q3: How would you handle a "hot tenant" monopolizing the worker pool?
**Answer**:
Currently, jobs are ordered by `next_run_at ASC`. If a single tenant enqueues 10,000 domains, they could starve other tenants. To prevent this, we can implement **fair-share round-robin leasing**:
1. Partition the claim query using PostgreSQL window functions: `ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY next_run_at ASC)`.
2. Limit each tenant to claiming at most $K$ jobs per polling interval.
3. At higher scale, partition queues by tenant into dedicated NATS/Kafka streams with individual worker concurrency limits per tenant.

---

### Q4: How do you prevent DNS rebinding in your SSRF protection?
**Answer**:
Static URL validation (`strings.Contains(url, "localhost")`) only protects against naive attacks. In a DNS rebinding attack, an attacker-controlled domain resolves to a public IP during initial validation, but returns a private IP (`169.254.169.254` or `127.0.0.1`) when the socket opens.
SurfaceWatch prevents this by injecting a custom `SafeDialContext` into the HTTP transport. At connect time, `SafeDialContext` resolves the hostname, validates *all* returned IPs against `restrictedCIDRs`, and pins the socket connection directly to the first validated IP address.
*Code reference*: `internal/api/ssrf.go`.

---

### Q5: Why did you use PostgreSQL `SKIP LOCKED` instead of an external message broker like RabbitMQ or Celery?
**Answer**:
1. **Transaction Atomicity**: Enqueueing a scan job occurs in the exact same ACID transaction that creates the `Scan` and `Asset` records. There are no dual-write consistency issues.
2. **Operational Simplicity**: Avoids operating, monitoring, and backing up a separate broker cluster.
3. **Lock-Free Concurrency**: `SKIP LOCKED` instructs the Postgres engine to skip rows locked by other transactions, preventing lock contention across worker pools.
*Code reference*: `docs/DESIGN_DECISIONS.md`.

---

### Q6: How does the Typosquatting generator work and what classes does it cover?
**Answer**:
Our permutation engine implements 7 distinct lookalike algorithms based on deceptive attacker techniques:
1. **Omission**: Drops characters one by one (`example` -> `xample`).
2. **Repetition**: Duplicates characters (`example` -> `exxample`).
3. **Transposition**: Swaps adjacent characters (`example` -> `eaxmple`).
4. **Adjacent Key**: Replaces characters with QWERTY keyboard neighbors (`a` -> `s, w, q, z`).
5. **Homoglyphs**: Replaces characters with visually similar numbers/symbols (`o` -> `0`, `l` -> `1`, `e` -> `3`).
6. **TLD Swap**: Replaces TLD with `.net`, `.org`, `.co`, `.io`, `.ai`.
7. **Hyphenation**: Inserts hyphens between characters (`ex-ample`).
The generator checks which generated domains actively resolve in DNS via passive resolution.
*Code reference*: `internal/collector/typosquat.go`.

---

### Q7: How does your secret scanner prevent storing raw credentials?
**Answer**:
In `internal/collector/collector.go`, we enforce a non-negotiable rule:
`RedactSecret(raw)` truncates the string, exposing only 2 to 4 prefix/suffix characters and masking the core: `AKIA...REDACTED...3FQA`.
`HashSecret(raw)` calculates `SHA-256(internal_salt + raw)` to generate an immutable fingerprint. Only this salted hash and redacted preview are stored in the database. Raw secrets never reach disk or database storage.

---

### Q8: What is Shannon entropy and why does it have higher false positive rates?
**Answer**:
Shannon entropy measures the average information content or randomness in a string of text: $H(X) = -\sum p(x) \log_2 p(x)$. True cryptographic secrets and API keys exhibit high randomness ($H > 4.5$ bits/char).
However, high entropy is not exclusive to secrets; random UUIDs, git commit SHAs, compiled base64 data, and non-secret hashes also exhibit high randomness. That is why our entropy detector explicitly suppresses UUIDs, hex SHAs, and known doc placeholders, though it still accounts for the majority of our false positives (precision ~44% as documented in `docs/EVALUATION.md`).

---

### Q9: How does the findings pipeline handle remediated findings that reappear?
**Answer**:
In `internal/pipeline/pipeline.go`, when a finding matches an existing fingerprint in the store, we inspect its current `status`. If an analyst had previously marked the finding as `resolved`, but the vulnerability is detected again in a later scan, the pipeline automatically transitions the status to `reopened` and logs a warning. If it was `new` or `acknowledged`, its status remains intact while `last_seen` and `occurrence_count` are updated.

---

### Q10: How do you achieve graceful shutdown in the worker pool?
**Answer**:
1. When a termination signal (`SIGINT`/`SIGTERM`) arrives, `server.Shutdown()` gives HTTP requests up to 10 seconds to finish.
2. `workerPool.Stop()` cancels the root context (`wp.cancel()`), stopping workers from claiming new jobs from the queue.
3. `wp.wg.Wait()` blocks until all active worker goroutines finish executing their currently claimed in-flight jobs.
4. Active heartbeat tickers and rate limiters clean up, ensuring zero jobs are dropped or left corrupted.
*Code reference*: `internal/scheduler/pool.go`.

---

### Q11: How do you prevent scanning targets outside the authorized scope?
**Answer**:
Every collector executes `GuardScope(scope, target)` as its very first instruction. The scope engine parses `scope.yaml` and normalizes target hostnames (stripping ports, schemes, and trailing dots). It verifies that the target matches an allowed root domain or wildcard rule, ensures it does not match an explicit exclusion, and defends against lookalike suffix attacks (`badexample.com` or `example.com.attacker.com`). If unauthorized, it returns a typed `*ErrOutOfScope` and immediately halts execution.
*Code reference*: `internal/scope/scope.go`.

---

### Q12: How does the system handle an HTTP 429 Too Many Requests response?
**Answer**:
`IsTransient(err)` classifies HTTP 429 and 5xx errors as transient, and 4xx client errors (400, 401, 403, 404) or `ErrOutOfScope` as permanent.
If an HTTP 429 response includes a `Retry-After` header (either in integer seconds or RFC 1123 HTTP date format), `BackoffCalculator.Calculate()` overrides the standard exponential backoff and strictly honors the remote service's requested sleep interval.
*Code reference*: `internal/scheduler/retry.go`.

---

### Q13: What is the purpose of the Circuit Breaker on each collector?
**Answer**:
If a third-party dependency (e.g. crt.sh or an external DNS server) goes down, repeatedly bombarding it causes connection timeouts and wastes worker pool threads.
Each collector has a circuit breaker (`internal/scheduler/circuitbreaker.go`) with states `Closed`, `Open`, and `Half-Open`. After 5 consecutive failures, the circuit opens for a 30-second cooldown period, during which calls fail fast immediately with `ErrCircuitOpen`. After the cooldown, a single probe request is permitted (Half-Open); if successful, normal operation resumes.

---

### Q14: How does cursor-based pagination work on the `/api/v1/findings` endpoint?
**Answer**:
Rather than offset-based pagination (`OFFSET 1000`) which degrades in performance on large datasets, cursor pagination uses a stable opaque token (an index or deterministic timestamp/ID cursor). Clients pass `?cursor=<val>&limit=50`. The response includes `findings: [...]` and a `next_cursor` token. When `next_cursor` is empty, the client has reached the end of the collection. Out-of-bounds cursors safely return an empty list without panics.
*Code reference*: `internal/api/handlers.go:HandleListFindings`.

---

### Q15: Why is `pprof` gated behind an environment variable?
**Answer**:
Exposing Go's standard `/debug/pprof` endpoints publicly in production exposes internal memory layouts, goroutine stack traces, cpu profiles, and execution details that attackers can use to map vulnerabilities, reverse-engineer internals, or trigger CPU-heavy profiling DoS attacks.
In SurfaceWatch, `RegisterPprof()` checks `os.Getenv("SURFACEWATCH_ENABLE_PPROF") == "true"`. If unset or false, the routes are never mounted and return `404 Not Found`.
*Code reference*: `internal/observability/metrics.go` and `internal/observability/metrics_test.go:TestPprofGating`.
