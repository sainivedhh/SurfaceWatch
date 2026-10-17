// Package scheduler provides a thread-safe Circuit Breaker per collector dependency.
package scheduler

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// CircuitState represents the health state of an external service dependency.
type CircuitState string

const (
	StateClosed   CircuitState = "closed"    // Normal operation: requests pass through
	StateOpen     CircuitState = "open"      // Failing: requests fail immediately without network call
	StateHalfOpen CircuitState = "half_open" // Testing recovery: allows limited probe requests
)

var ErrCircuitOpen = errors.New("circuit breaker is open: dependency is temporarily down")

// CircuitBreaker guards a collector against cascading failures.
type CircuitBreaker struct {
	mu               sync.Mutex
	name             string
	state            CircuitState
	failureThreshold int
	consecutiveFails int
	cooldown         time.Duration
	openedAt         time.Time
}

// NewCircuitBreaker constructs a circuit breaker with failure threshold and cooldown duration.
func NewCircuitBreaker(name string, failureThreshold int, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:             name,
		state:            StateClosed,
		failureThreshold: failureThreshold,
		cooldown:         cooldown,
	}
}

// Execute runs the operation if the circuit allows, or returns ErrCircuitOpen immediately.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.beforeExecution(); err != nil {
		return err
	}

	err := fn()
	cb.afterExecution(err)
	return err
}

func (cb *CircuitBreaker) beforeExecution() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case StateOpen:
		// Check if cooldown has elapsed to enter Half-Open probe state
		if now.Sub(cb.openedAt) >= cb.cooldown {
			cb.state = StateHalfOpen
			return nil
		}
		return fmt.Errorf("%w for collector %q (cooling down for %s)", ErrCircuitOpen, cb.name, cb.cooldown-now.Sub(cb.openedAt))
	case StateHalfOpen:
		// In half-open, allow trial request
		return nil
	default:
		// StateClosed: healthy
		return nil
	}
}

func (cb *CircuitBreaker) afterExecution(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	if err != nil {
		cb.consecutiveFails++
		if cb.state == StateHalfOpen || cb.consecutiveFails >= cb.failureThreshold {
			cb.state = StateOpen
			cb.openedAt = now
		}
	} else {
		// Success resets the circuit breaker back to Closed
		cb.state = StateClosed
		cb.consecutiveFails = 0
	}
}

// State returns current circuit status.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}
