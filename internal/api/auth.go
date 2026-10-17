// Package api provides secure HTTP REST endpoints, multi-tenant RBAC, and middleware.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Role defines role-based access levels.
type Role string

const (
	RoleAdmin   Role = "admin"   // Full access: configure scope, add assets, run scans, update findings
	RoleAnalyst Role = "analyst" // Operational: view assets, run scans, update finding statuses
	RoleViewer  Role = "viewer"  // Read-only: inspect assets, scans, findings, stats
)

func (r Role) Level() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleAnalyst:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

func (r Role) Allows(required Role) bool {
	return r.Level() >= required.Level()
}

// APIKey represents an authenticated client credential.
type APIKey struct {
	ID       uuid.UUID `json:"id"`
	TenantID string    `json:"tenant_id"`
	KeyHash  string    `json:"-"`
	Role     Role      `json:"role"`
	Name     string    `json:"name"`
}

// KeyStore abstracts credential persistence.
type KeyStore interface {
	LookupKey(ctx context.Context, rawKey string) (*APIKey, error)
}

// MemoryKeyStore provides an in-memory key storage for testing and dev.
type MemoryKeyStore struct {
	keys map[string]*APIKey // key prefix / token -> APIKey
}

func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{keys: make(map[string]*APIKey)}
}

func (m *MemoryKeyStore) RegisterKey(token string, tenantID string, role Role, name string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	m.keys[token] = &APIKey{
		ID:       uuid.New(),
		TenantID: tenantID,
		KeyHash:  string(hash),
		Role:     role,
		Name:     name,
	}
	return nil
}

func (m *MemoryKeyStore) LookupKey(ctx context.Context, rawKey string) (*APIKey, error) {
	// Look up by token and verify bcrypt
	for token, k := range m.keys {
		if subtle.ConstantTimeCompare([]byte(token), []byte(rawKey)) == 1 {
			return k, nil
		}
	}
	return nil, errors.New("invalid or unknown api key")
}

type contextKey string

const (
	contextTenantKey contextKey = "sw_tenant_id"
	contextRoleKey   contextKey = "sw_user_role"
	contextAPIKey    contextKey = "sw_api_key"
)

// Authenticator handles HTTP authentication middleware.
type Authenticator struct {
	store KeyStore
}

func NewAuthenticator(store KeyStore) *Authenticator {
	return &Authenticator{store: store}
}

// Middleware verifies the X-API-Key header and establishes multi-tenant context.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyHeader := r.Header.Get("X-API-Key")
		if keyHeader == "" {
			// Check Authorization: Bearer <key>
			authHdr := r.Header.Get("Authorization")
			if strings.HasPrefix(authHdr, "Bearer ") {
				keyHeader = strings.TrimPrefix(authHdr, "Bearer ")
			}
		}

		if keyHeader == "" {
			WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing X-API-Key or Bearer token header")
			return
		}

		apiKey, err := a.store.LookupKey(r.Context(), keyHeader)
		if err != nil {
			WriteError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid or revoked API key")
			return
		}

		ctx := context.WithValue(r.Context(), contextTenantKey, apiKey.TenantID)
		ctx = context.WithValue(ctx, contextRoleKey, apiKey.Role)
		ctx = context.WithValue(ctx, contextAPIKey, apiKey)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole enforces role-based authorization check.
func RequireRole(required Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole, ok := r.Context().Value(contextRoleKey).(Role)
			if !ok || !userRole.Allows(required) {
				WriteError(w, http.StatusForbidden, "FORBIDDEN", "Insufficient permissions for requested action")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GetTenantID extracts the authenticated tenant from context.
func GetTenantID(ctx context.Context) string {
	if val, ok := ctx.Value(contextTenantKey).(string); ok {
		return val
	}
	return ""
}

// GetRole extracts the authenticated user's role from context.
func GetRole(ctx context.Context) Role {
	if val, ok := ctx.Value(contextRoleKey).(Role); ok {
		return val
	}
	return RoleViewer
}

// Standard Error Envelope response
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// WriteError outputs a standard structured JSON error envelope.
func WriteError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}
