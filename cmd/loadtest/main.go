// Package main provides a load-testing utility for the SurfaceWatch API.
// It reports total requests, duration, throughput (req/sec), and p50, p95, p99 latency percentiles.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

func main() {
	targetURL := flag.String("url", "http://localhost:8080/healthz", "Target endpoint URL")
	concurrency := flag.Int("c", 10, "Concurrency level (number of workers)")
	totalRequests := flag.Int("n", 2000, "Total number of HTTP requests to execute")
	apiKey := flag.String("key", "", "Optional API Key for authenticated endpoints")
	flag.Parse()

	fmt.Println("=================================================================")
	fmt.Printf("Starting SurfaceWatch Load Test\n")
	fmt.Printf("Target: %s | Total Requests: %d | Concurrency: %d\n", *targetURL, *totalRequests, *concurrency)
	fmt.Println("=================================================================")

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	reqsPerWorker := *totalRequests / *concurrency
	var wg sync.WaitGroup

	latencies := make([]time.Duration, 0, *totalRequests)
	var mu sync.Mutex
	statusCodes := make(map[int]int)

	startTime := time.Now()

	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localLatencies := make([]time.Duration, 0, reqsPerWorker)
			localStatusCodes := make(map[int]int)

			for i := 0; i < reqsPerWorker; i++ {
				req, err := http.NewRequest(http.MethodGet, *targetURL, nil)
				if err != nil {
					continue
				}
				if *apiKey != "" {
					req.Header.Set("X-API-Key", *apiKey)
				}

				start := time.Now()
				resp, err := client.Do(req)
				duration := time.Since(start)

				if err == nil {
					localStatusCodes[resp.StatusCode]++
					resp.Body.Close()
				} else {
					localStatusCodes[0]++
				}
				localLatencies = append(localLatencies, duration)
			}

			mu.Lock()
			latencies = append(latencies, localLatencies...)
			for code, count := range localStatusCodes {
				statusCodes[code] += count
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	totalDuration := time.Since(startTime)

	if len(latencies) == 0 {
		fmt.Println("No completed requests.")
		return
	}

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	rps := float64(len(latencies)) / totalDuration.Seconds()
	p50 := latencies[int(float64(len(latencies))*0.50)]
	p95 := latencies[int(float64(len(latencies))*0.95)]
	p99 := latencies[int(float64(len(latencies))*0.99)]

	fmt.Println("\n--- RESULTS ---")
	fmt.Printf("Total Requests:       %d\n", len(latencies))
	fmt.Printf("Total Elapsed Time:   %s\n", totalDuration.Round(time.Millisecond))
	fmt.Printf("Throughput:           %.2f req/sec\n", rps)
	fmt.Printf("Latency (p50):        %s\n", p50.Round(time.Microsecond))
	fmt.Printf("Latency (p95):        %s\n", p95.Round(time.Microsecond))
	fmt.Printf("Latency (p99):        %s\n", p99.Round(time.Microsecond))
	fmt.Printf("Status Codes:         %+v\n", statusCodes)
	fmt.Println("=================================================================")
}
