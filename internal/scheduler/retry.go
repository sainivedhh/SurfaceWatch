// Package scheduler provides exponential backoff with full jitter and Retry-After handling.
package scheduler

import (
	"errors"
	"math"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// HTTPStatusError represents an HTTP error response containing status code and optional Retry-After header.
type HTTPStatusError struct {
	StatusCode int
	RetryAfter *time.Duration
	Message    string
}

func (e *HTTPStatusError) Error() string {
	return e.Message
}

// ParseRetryAfter parses an HTTP Retry-After header value (either seconds or RFC1123 date).
func ParseRetryAfter(headerVal string) *time.Duration {
	val := strings.TrimSpace(headerVal)
	if val == "" {
		return nil
	}
	// Try integer seconds
	if secs, err := strconv.Atoi(val); err == nil && secs >= 0 {
		d := time.Duration(secs) * time.Second
		return &d
	}
	// Try RFC1123 HTTP date
	if t, err := http.ParseTime(val); err == nil {
		diff := time.Until(t)
		if diff < 0 {
			diff = 0
		}
		return &diff
	}
	return nil
}

// IsTransient evaluates whether an error is temporary and safe to retry.
// Permanent errors (such as ErrOutOfScope or HTTP 400/401/403/404) return false.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}

	// Scope violations are strictly permanent: never retry
	if scope.IsErrOutOfScope(err) {
		return false
	}

	// Check typed HTTPStatusError
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		// 429 Too Many Requests and 5xx Server Errors are transient
		if httpErr.StatusCode == http.StatusTooManyRequests ||
			httpErr.StatusCode == http.StatusInternalServerError ||
			httpErr.StatusCode == http.StatusBadGateway ||
			httpErr.StatusCode == http.StatusServiceUnavailable ||
			httpErr.StatusCode == http.StatusGatewayTimeout {
			return true
		}
		// 4xx client errors (400, 401, 403, 404) are permanent
		return false
	}

	// Check net.Error timeouts / temporary errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	// Common transient network string indicators
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "temporary failure") ||
		strings.Contains(msg, "too many requests") ||
		strings.Contains(msg, "429") {
		return true
	}

	return false
}

// BackoffCalculator computes the delay for the next retry attempt using exponential backoff with full jitter.
type BackoffCalculator struct {
	BaseInterval time.Duration
	MaxInterval  time.Duration
	rng          *rand.Rand
}

func NewBackoffCalculator(base, max time.Duration) *BackoffCalculator {
	return &BackoffCalculator{
		BaseInterval: base,
		MaxInterval:  max,
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Calculate returns the duration to sleep before attempt N.
// If retryAfter is provided (e.g. from an HTTP 429 header), it honors that interval.
func (b *BackoffCalculator) Calculate(attempt int, retryAfter *time.Duration) time.Duration {
	if retryAfter != nil && *retryAfter > 0 {
		return *retryAfter
	}

	if attempt <= 0 {
		attempt = 1
	}

	// Exponential backoff: base * 2^(attempt-1)
	multiplier := math.Pow(2, float64(attempt-1))
	maxSleep := float64(b.BaseInterval) * multiplier
	if maxSleep > float64(b.MaxInterval) {
		maxSleep = float64(b.MaxInterval)
	}

	// Full Jitter: Uniform random between 0 and maxSleep
	jittered := time.Duration(rand.Float64() * maxSleep)
	if jittered < b.BaseInterval {
		jittered = b.BaseInterval
	}
	return jittered
}
