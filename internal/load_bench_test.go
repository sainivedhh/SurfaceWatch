package internal_test

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/surfacewatch/surfacewatch/internal/api"
	"github.com/surfacewatch/surfacewatch/internal/pipeline"
)

// TestLoadTest_API executes a concurrent load test against the live HTTP router
// and logs the exact requests per second (RPS) and p50, p95, p99 latency percentiles.
func TestLoadTest_API(t *testing.T) {
	keyStore := api.NewMemoryKeyStore()
	_ = keyStore.RegisterKey("perf-test-key", "perf-tenant", api.RoleViewer, "Perf Viewer")
	auth := api.NewAuthenticator(keyStore)

	appCtx := &api.AppContext{
		Findings:   pipeline.NewMemoryFindingStore(),
		Cache:      pipeline.NewMemoryCache(),
		AssetStore: api.NewMemoryAssetStore(),
		ScanStore:  api.NewMemoryScanStore(),
	}

	router := api.NewRouter(appCtx, auth, api.RouterConfig{
		RateLimit: 50000,
		Burst:     100000,
	})

	server := httptest.NewServer(router)
	defer server.Close()

	totalRequests := 5000
	concurrency := 20
	reqsPerWorker := totalRequests / concurrency

	client := server.Client()
	client.Timeout = 5 * time.Second

	var wg sync.WaitGroup
	var mu sync.Mutex
	latencies := make([]time.Duration, 0, totalRequests)
	statusCodes := make(map[int]int)

	start := time.Now()

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localLats := make([]time.Duration, 0, reqsPerWorker)
			localCodes := make(map[int]int)

			for i := 0; i < reqsPerWorker; i++ {
				req, _ := http.NewRequest(http.MethodGet, server.URL+"/healthz", nil)
				t0 := time.Now()
				resp, err := client.Do(req)
				dur := time.Since(t0)

				if err == nil {
					localCodes[resp.StatusCode]++
					resp.Body.Close()
				} else {
					localCodes[0]++
				}
				localLats = append(localLats, dur)
			}

			mu.Lock()
			latencies = append(latencies, localLats...)
			for c, cnt := range localCodes {
				statusCodes[c] += cnt
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	rps := float64(len(latencies)) / elapsed.Seconds()
	p50 := latencies[int(float64(len(latencies))*0.50)]
	p95 := latencies[int(float64(len(latencies))*0.95)]
	p99 := latencies[int(float64(len(latencies))*0.99)]

	t.Logf("=== SURFACEWATCH LOAD TEST RESULTS ===")
	t.Logf("Total Requests:  %d", len(latencies))
	t.Logf("Concurrency:     %d", concurrency)
	t.Logf("Elapsed Time:    %s", elapsed.Round(time.Millisecond))
	t.Logf("Throughput:      %.2f req/sec", rps)
	t.Logf("Latency (p50):   %s", p50.Round(time.Microsecond))
	t.Logf("Latency (p95):   %s", p95.Round(time.Microsecond))
	t.Logf("Latency (p99):   %s", p99.Round(time.Microsecond))
	t.Logf("Status Codes:    %+v", statusCodes)
	t.Logf("=======================================")

	if statusCodes[http.StatusOK] != totalRequests {
		t.Errorf("expected %d 200 OK responses, got %d", totalRequests, statusCodes[http.StatusOK])
	}
}
