// Package api provides HMAC-signed webhook delivery, retry with backoff, and dead-lettering.
package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/model"
)

// WebhookSubscription defines a registered endpoint for finding notifications.
type WebhookSubscription struct {
	ID        uuid.UUID `json:"id"`
	TenantID  string    `json:"tenant_id"`
	URL       string    `json:"url"`
	Secret    string    `json:"secret"` // Shared secret for HMAC-SHA256 signature
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// DeadLetterEntry captures failed deliveries for post-mortem investigation.
type DeadLetterEntry struct {
	ID          uuid.UUID `json:"id"`
	WebhookID   uuid.UUID `json:"webhook_id"`
	TenantID    string    `json:"tenant_id"`
	TargetURL   string    `json:"target_url"`
	PayloadJSON string    `json:"payload_json"`
	LastError   string    `json:"last_error"`
	Attempts    int       `json:"attempts"`
	FailedAt    time.Time `json:"failed_at"`
}

// ComputeHMAC generates the hexadecimal HMAC-SHA256 signature for a payload.
func ComputeHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// WebhookDispatcher manages alert dissemination.
type WebhookDispatcher struct {
	client      *http.Client
	deadLetters []DeadLetterEntry
	mu          sync.Mutex
	logger      *slog.Logger
	maxAttempts int
}

func NewWebhookDispatcher(client *http.Client, logger *slog.Logger) *WebhookDispatcher {
	if client == nil {
		client = NewSafeHTTPClient(5 * time.Second)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &WebhookDispatcher{
		client:      client,
		deadLetters: make([]DeadLetterEntry, 0),
		logger:      logger,
		maxAttempts: 3,
	}
}

// DispatchFindingAlert delivers an HMAC-signed finding event to a webhook subscriber.
func (d *WebhookDispatcher) DispatchFindingAlert(ctx context.Context, sub WebhookSubscription, finding *model.Finding) error {
	payloadBytes, err := json.Marshal(map[string]any{
		"event":     "finding.detected",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"tenant_id": sub.TenantID,
		"finding":   finding,
	})
	if err != nil {
		return fmt.Errorf("failed to encode webhook payload: %w", err)
	}

	sig := ComputeHMAC(payloadBytes, sub.Secret)

	var lastErr error
	for attempt := 1; attempt <= d.maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.URL, bytes.NewReader(payloadBytes))
		if err != nil {
			lastErr = err
			break
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Hub-Signature-256", "sha256="+sig)
		req.Header.Set("User-Agent", "SurfaceWatch-Webhook/1.0")

		resp, err := d.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// Delivery success
				return nil
			}
			lastErr = fmt.Errorf("webhook endpoint returned status %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		// If SSRF blocked or invalid URL, do not retry
		if errorsIsSSRF(lastErr) {
			break
		}

		// Exponential backoff between attempts
		time.Sleep(time.Duration(attempt*100) * time.Millisecond)
	}

	// Delivery permanently failed: store in dead-letter table
	d.recordDeadLetter(sub, string(payloadBytes), lastErr)
	return lastErr
}

func (d *WebhookDispatcher) recordDeadLetter(sub WebhookSubscription, payload string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	errMsg := "unknown error"
	if err != nil {
		errMsg = err.Error()
	}

	entry := DeadLetterEntry{
		ID:          uuid.New(),
		WebhookID:   sub.ID,
		TenantID:    sub.TenantID,
		TargetURL:   sub.URL,
		PayloadJSON: payload,
		LastError:   errMsg,
		Attempts:    d.maxAttempts,
		FailedAt:    time.Now().UTC(),
	}

	d.deadLetters = append(d.deadLetters, entry)
	d.logger.Error("Webhook permanently failed: moved to dead-letter queue",
		"webhook_id", sub.ID,
		"target_url", sub.URL,
		"error", errMsg)
}

func (d *WebhookDispatcher) GetDeadLetters() []DeadLetterEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]DeadLetterEntry, len(d.deadLetters))
	copy(out, d.deadLetters)
	return out
}

func errorsIsSSRF(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrSSRFBlocked || (err != nil && (contains(err.Error(), "SSRF protection") || contains(err.Error(), "restricted IP")))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && bytes.Contains([]byte(s), []byte(substr))))
}
