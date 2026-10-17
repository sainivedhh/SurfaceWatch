# Architectural & Design Decisions

This document details the trade-offs, rationale, and evolution paths behind the core architectural decisions in SurfaceWatch.

---

## 1. Job Leasing: Why PostgreSQL `FOR UPDATE SKIP LOCKED` vs RabbitMQ/Kafka/Celery?

### The Decision
SurfaceWatch implements distributed job queuing and leasing directly in PostgreSQL using `SELECT ... FOR UPDATE SKIP LOCKED` rather than introducing a separate message broker (e.g. RabbitMQ, Kafka, SQS, or Celery).

### Trade-Offs & Rationale
1. **Single Source of Truth & ACID Guarantees**:
   - In attack-surface monitoring, job scheduling is directly tied to asset registration, scan records, and historical findings.
   - When an asset or scan is created, jobs are enqueued in the **exact same database transaction**. With an external broker, achieving dual-write consistency requires the Outbox Pattern and two-phase commit mechanisms.
2. **Deterministic Locking without Head-of-Line Blocking**:
   - Standard row locks (`FOR UPDATE`) block competing workers until the lock is released.
   - `SKIP LOCKED` instructs the database engine to bypass already-locked rows and claim the first available unleased row immediately. This achieves lock-free concurrent consumption across dozens of worker nodes without lock contention.
3. **Dead Worker Recovery via Leases**:
   - If a worker dies mid-scan (OOM, container eviction, network cut), traditional brokers require complicated ACK timeouts and redelivery policies.
   - In our schema, the lease timestamp `leased_until` naturally expires. A peer worker automatically claims the job on its next polling cycle:
     ```sql
     WHERE (status = 'queued' AND next_run_at <= NOW())
        OR (status = 'leased' AND leased_until < NOW() AND attempts < max_attempts)
     ```
4. **Operational Simplicity**:
   - Zero additional broker clusters to provision, monitor, patch, or replicate in early-to-mid stage enterprise deployments.

---

## 2. Rate Limiting: Why Per-Host Token Bucket?

### The Decision
Rate limiting in SurfaceWatch is enforced **per target host** rather than globally or per collector.

### Trade-Offs & Rationale
1. **Target Infrastructure Safety**:
   - In digital risk and attack-surface monitoring, an operator may launch scans against 50 different domains simultaneously.
   - A global rate limiter of 50 req/sec could direct all 50 requests to a single target in 1 second, triggering target WAFs, DDoS alarms, or service disruption.
2. **Fair Multi-Target Scheduling**:
   - Token buckets (`golang.org/x/time/rate`) allow bursts for responsive scanning while smoothly replenishing tokens.
   - If `api.example.com` is actively being queried, workers processing `partner.org` continue at full speed without waiting on `api.example.com`'s rate limiter.
3. **Automatic Normalization**:
   - All targets are normalized (schemes stripped, ports stripped, FQDN trailing dots removed) so `https://example.com:443/` and `http://example.com/` share the exact same token bucket.

---

## 3. Caching & Invalidation Strategy

### The Decision
SurfaceWatch employs a **Write-Through Invalidation** caching pattern with **Graceful Fallback**.

### Mechanics:
1. **Hot Reads**:
   - Finding lookups (`GET /api/v1/findings/{id}`) and recent asset profiles are checked in Redis first (key format `finding:<id>`) with a 15-minute TTL.
2. **Write Invalidation**:
   - On finding creation or status update (`PATCH /api/v1/findings/{id}/status`), the cache key is actively updated or deleted.
3. **Graceful Degradation (Circuit-Safe)**:
   - If Redis crashes, experiences network partitions, or runs out of memory, SurfaceWatch logs a warning and queries PostgreSQL directly.
   - System correctness is never compromised; performance drops gracefully from sub-millisecond memory reads to low-millisecond disk reads.

---

## 4. What Changes at 100x Scale?

At 100x scale (**10,000 requests/sec API load**, **1,000,000 monitored assets**, **100+ distributed worker nodes**), the following architectural evolutions would be implemented:

### 4.1 Transition from Postgres SKIP LOCKED to Partitioned Kafka / NATS JetStream
- While Postgres `SKIP LOCKED` scales comfortably to several thousand jobs/sec, at 100,000+ jobs/min table bloat and WAL write throughput on the `jobs` table become a bottleneck.
- **Action**: Transition job dispatching to **NATS JetStream** or **Apache Kafka** partitioned by `tenant_id` and `target_host`. Maintain scan metadata in PostgreSQL while ephemeral execution queues live in the stream.

### 4.2 Distributed Redis Cluster for Global Host Rate Limiting
- The current token-bucket limiter runs in-process per worker node. Across 100 distributed worker nodes, 100 separate 5 req/sec limiters could theoretically hit a single host with 500 req/sec.
- **Action**: Migrate per-host rate limiting to Redis using a Lua-scripted sliding window or token bucket algorithm (`CL.THROTTLE` / RedisCell), ensuring a unified rate across all cluster nodes.

### 4.3 Database Read Replicas & Tenant Sharding
- **Action**: Implement Citus or PostgreSQL logical sharding by `tenant_id`.
- Introduce read-replicas for analytical queries (`GET /api/v1/stats/summary` and finding list filtering), leaving primary nodes dedicated exclusively to job leasing and finding upsertion.

### 4.4 Sharded Typosquat Permutation Generation
- For large enterprise brands with hundreds of domain variations, DNS resolution of thousands of permutations can be delegated to an asynchronous fan-out worker pool using mass-resolver pools (e.g. distributed DNS resolvers with round-robin resolver IPs).
