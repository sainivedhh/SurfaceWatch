# --- Build Stage ---
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install git and ca-certificates for dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Cache Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Compile statically linked binary without CGO
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -extldflags '-static'" \
    -o /bin/surfacewatch ./cmd/server

# --- Final Runtime Stage ---
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy timezone data & certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy compiled binary and scope configuration
COPY --from=builder /bin/surfacewatch /app/surfacewatch
COPY --from=builder /app/scope.yaml /app/scope.yaml

# Run strictly as unprivileged non-root user (UID 65532 in distroless:nonroot)
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/app/surfacewatch"]
CMD ["-port", "8080", "-scope", "/app/scope.yaml"]
