.PHONY: all build test test-race cover bench run docker-build docker-up docker-down clean help

SHELL := /bin/sh
GO ?= go

all: build test

## build: Compile the SurfaceWatch server and CLI binaries
build:
	$(GO) build -o bin/surfacewatch ./cmd/server
	$(GO) build -o bin/loadtest ./cmd/loadtest

## test: Run all unit and failure tests
test:
	$(GO) test -v ./internal/...

## test-race: Run all tests with race detector enabled
test-race:
	$(GO) test -race -v ./internal/...

## cover: Run tests and generate coverage report
cover:
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./internal/...
	$(GO) tool cover -func=coverage.out

## bench: Execute performance micro-benchmarks
bench:
	$(GO) test -bench="." -benchmem ./internal

## eval: Run honest secret detector evaluation across Dev and Holdout sets
eval:
	$(GO) test -v -run TestDetectorEvaluation_DevAndHoldout ./internal/collector

## run: Run the server locally
run:
	$(GO) run ./cmd/server -port 8080 -scope scope.yaml

## docker-build: Build the multi-stage Docker container
docker-build:
	docker build -t surfacewatch:latest .

## docker-up: Start PostgreSQL, Redis, and SurfaceWatch via Docker Compose
docker-up:
	docker-compose up -d

## docker-down: Stop all containers and teardown networks
docker-down:
	docker-compose down

## clean: Remove compiled binaries and temporary artifacts
clean:
	rm -rf bin/ coverage.out

## help: Display available make targets
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':'
