# Go Idioms & Language Patterns in SurfaceWatch

This guide explains every key Go idiom, concurrency construct, and design pattern used across the SurfaceWatch codebase to prepare you for backend engineering interviews.

---

## 1. Goroutines & Worker Concurrency

### What is it?
A **goroutine** is a lightweight thread managed by the Go runtime (not an OS thread). A goroutine typically starts with just ~2 KB of stack space (compared to 1–2 MB for OS threads), allowing Go applications to run thousands of concurrent tasks without substantial memory overhead.

### How SurfaceWatch uses it:
In `internal/scheduler/pool.go`:
```go
for i := 0; i < wp.cfg.Concurrency; i++ {
    wp.wg.Add(1)
    go wp.runWorker(i)
}
```
Each worker runs as a dedicated goroutine claiming and executing scan jobs concurrently.

---

## 2. Channels & Signal Communication

### What is it?
Channels are typed conduits through which you can send and receive values with the channel operator `<-`. They allow goroutines to synchronize execution and communicate safely without explicit shared-memory locking ("*Do not communicate by sharing memory; instead, share memory by communicating*").

### How SurfaceWatch uses it:
1. **OS Signal Trapping for Graceful Shutdown** (`cmd/server/main.go`):
   ```go
   sigChan := make(chan os.Signal, 1)
   signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
   <-sigChan // Blocks until OS sends interrupt (Ctrl+C)
   ```
2. **Ticker Channels for Background Heartbeats** (`internal/scheduler/pool.go`):
   ```go
   ticker := time.NewTicker(wp.cfg.HeartbeatInterval)
   defer ticker.Stop()
   for {
       select {
       case <-hbCtx.Done():
           return
       case <-ticker.C:
           _ = wp.store.Heartbeat(...)
       }
   }
   ```

---

## 3. Context (`context.Context`)

### What is it?
The `context` package carries deadlines, cancellation signals, and request-scoped values across API boundaries and between goroutines.

### How SurfaceWatch uses it:
1. **Cancellation & Graceful Draining**:
   When the server shuts down, `wp.cancel()` broadcasts cancellation across all active workers. Any network query listening to `ctx.Done()` immediately aborts.
2. **Timeouts & Deadlines**:
   Preventing hanging HTTP or DNS operations:
   ```go
   ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
   defer cancel()
   ```
3. **Request-Scoped Tenant Context**:
   Passing validated tenant IDs safely through HTTP middleware without modifying function signatures:
   ```go
   ctx := context.WithValue(r.Context(), contextTenantKey, apiKey.TenantID)
   ```

---

## 4. Interfaces & Duck Typing

### What is it?
In Go, interfaces are satisfied **implicitly** (structural typing or "duck typing"). If a type implements all methods declared in an interface, it implements that interface automatically without an explicit `implements` keyword.

### How SurfaceWatch uses it:
Every external dependency is abstracted behind an interface so the entire test suite runs offline with zero live network calls:
- `Collector` interface (`internal/collector/collector.go`) -> Swapped with `FakeCollector`
- `HTTPClient` interface (`internal/collector/ct.go`) -> Swapped with `FakeHTTPClient`
- `Resolver` interface (`internal/collector/dns.go`) -> Swapped with `FakeResolver`
- `Store` interface (`internal/scheduler/store.go`) -> Implemented by both PostgreSQL and `MemoryStore`
- `Cache` interface (`internal/pipeline/cache.go`) -> Implemented by both `RedisCache` and `MemoryCache`

---

## 5. Error Wrapping & Inspection (`%w`, `errors.Is`, `errors.As`)

### What is it?
Go 1.13 introduced error wrapping using `fmt.Errorf("...: %w", err)` to preserve causal error chains while adding context.
- `errors.Is(err, target)`: Checks whether any error in the chain matches the target (replaces fragile `err == target`).
- `errors.As(err, &target)`: Finds the first error in the chain matching a specific typed struct.

### How SurfaceWatch uses it:
In `internal/scope/scope.go`:
```go
func IsErrOutOfScope(err error) bool {
    var targetErr *ErrOutOfScope
    return errors.As(err, &targetErr)
}
```
And in transient error evaluation (`internal/scheduler/retry.go`):
```go
var httpErr *HTTPStatusError
if errors.As(err, &httpErr) {
    if httpErr.StatusCode == http.StatusTooManyRequests { ... }
}
```

---

## 6. The `defer` Statement & Resource Reclamation

### What is it?
`defer` schedules a function call to execute immediately before the surrounding function returns. Defers execute in Last-In-First-Out (LIFO) order.

### How SurfaceWatch uses it:
Guaranteeing that sockets, files, and mutexes are cleaned up regardless of whether the function returns normally or via an early error `return`:
```go
file, err := os.Open(path)
if err != nil {
    return nil, err
}
defer file.Close() // Guaranteed to run on any exit path
```
And releasing mutex locks:
```go
s.mu.Lock()
defer s.mu.Unlock()
```

---

## 7. Synchronization Primitives (`sync.WaitGroup`, `sync.Mutex`, `atomic`)

### What is it?
Low-level synchronization tools for memory safety and goroutine coordination.
- `sync.WaitGroup`: Waits for a collection of goroutines to finish (`Add`, `Done`, `Wait`).
- `sync.Mutex` / `sync.RWMutex`: Mutual exclusion lock preventing concurrent read/write data races.
- `sync/atomic`: Hardware-level atomic operations for lockless integer counters (e.g. `atomic.AddInt32`).

### How SurfaceWatch uses it:
- `sync.WaitGroup` coordinates worker pool graceful shutdown: `wp.Stop()` triggers `wp.wg.Wait()`, ensuring zero jobs are dropped in flight.
- `sync.RWMutex` protects hot read caches while allowing concurrent parallel reads.
