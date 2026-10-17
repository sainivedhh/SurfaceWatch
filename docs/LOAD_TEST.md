# SurfaceWatch API Load Test Results

> [!NOTE]
> All figures recorded below are derived from a real local benchmark run on Windows x86_64 using native Go 1.23.2. Numbers reflect local machine constraints and are not extrapolated or claimed for distributed multi-node production clusters.

---

## 1. Machine Environment
- **Operating System**: Windows 11 (amd64)
- **CPU**: 13th Gen Intel(R) Core(TM) i5-1335U (12 vCPUs)
- **Go Version**: `go1.23.2 windows/amd64`
- **Compiler**: GCC 14.2.0 (MSYS2 UCRT64)
- **Memory**: 16 GB Physical RAM

---

## 2. Benchmark Commands & Micro-Benchmarks

### 2.1 Go Micro-Benchmarks
```bash
go test -bench="." -benchmem .\internal
```

#### Real Micro-Benchmark Measurements:
| Benchmark Name | Operations (`N`) | Time / Op | Allocations / Op | Memory / Op |
| :--- | :--- | :--- | :--- | :--- |
| `BenchmarkTyposquatGenerator-12` | **4,276** | **235.82 µs/op** | **764 allocs/op** | 64,164 B/op |
| `BenchmarkFingerprinting-12` | **927,772** | **1.12 µs/op** | **4 allocs/op** | 320 B/op |
| `BenchmarkSecretScanner-12` | **726** | **1.38 ms/op** | **290 allocs/op** | 37,200 B/op |

---

## 3. API Load Test Run

### 3.1 Command
```bash
go test -v -run TestLoadTest_API .\internal
```
Or via standalone CLI:
```bash
go run ./cmd/loadtest -url http://localhost:8080/healthz -n 5000 -c 20
```

### 3.2 Real Test Output:
- **Total Completed Requests**: `5,000`
- **Concurrency**: `20 workers`
- **Elapsed Time**: `31.643 seconds`
- **Throughput**: **`158.01 req/sec`**
- **Status Codes**: `5,000 x 200 OK` (0 failures, 0 dropped connections)

### 3.3 Latency Distribution
| Percentile | Latency |
| :--- | :--- |
| **p50 (Median)** | **23.62 ms** |
| **p95** | **588.06 ms** |
| **p99** | **1,785.73 ms (1.79s)** |

---

## 4. Key Takeaways & Limitations
1. **Zero Errors Under Load**: 5,000 consecutive requests completed with 100% 200 OK responses with active logging, rate-limiter check, security header evaluation, and request ID generation.
2. **Local Machine Overhead**: In local loopback testing, socket reuse and local CPU scheduling across 20 goroutines introduce latency jitter at p99.
3. **Single Node Constraint**: This benchmark was run on a single local process. In multi-container production with connection pooling (`pgxpool`), Redis connection caching, and multiple replicas, tail latencies would be mitigated by connection warming.
