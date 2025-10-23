# Go LDAP Red Hat - Makefile
# ===========================

.PHONY: help build test test-verbose test-integration test-unit clean install lint fmt vet deps check cli run-cli benchmark coverage release

# Default target
help: ## Show this help message
	@echo "Go LDAP Red Hat - Available Commands:"
	@echo "===================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Build commands
build: ## Build the library
	@echo "Building library..."
	go build .
	@echo "Library build complete"

cli: ## Build the CLI tool
	@echo "Building CLI tool..."
	go build -o bin/ldapcheck ./cmd/ldapcheck
	@echo "CLI tool built: bin/ldapcheck"

install: ## Install dependencies
	@echo "Installing dependencies..."
	go mod tidy
	go mod download
	@echo "Dependencies installed"

# Test commands
test: ## Run all tests
	@echo "Running all tests..."
	go test -v .
	@echo "All tests completed"

test-unit: ## Run unit tests only (skip integration)
	@echo "Running unit tests..."
	go test -v . -short
	@echo "Unit tests completed"

test-integration: ## Run integration tests only
	@echo "Running integration tests..."
	go test -v . -run TestLDAP
	@echo "Integration tests completed"

test-verbose: ## Run tests with extra verbose output
	@echo "Running verbose tests..."
	go test -v . -run TestSuiteOverview
	go test -v .
	@echo "Verbose tests completed"

benchmark: ## Run performance benchmarks
	@echo "Running benchmarks..."
	go test -bench=. -benchmem .
	@echo "Benchmarks completed"

coverage: ## Generate test coverage report
	@echo "Generating coverage report..."
	go test -coverprofile=coverage.out .
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Code quality commands
lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run || echo "Warning: Install golangci-lint for better linting"
	@echo "Linting completed"

fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...
	@echo "Code formatted"

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...
	@echo "Vet completed"

check: fmt vet test ## Run all code quality checks
	@echo "All quality checks passed"

# Development commands
run-cli: cli ## Build and run CLI with example
	@echo "Running CLI example..."
	@echo "Usage: make run-cli USER=jemedina"
	@if [ -z "$(USER)" ]; then \
		echo "Please specify USER: make run-cli USER=jemedina"; \
	else \
		echo "Searching for user: $(USER)"; \
		LDAP_URL=ldap://apps-ldap.corp.redhat.com:389 \
		LDAP_BIND_DN=uid=pco-deleted-users-query,ou=users,dc=redhat,dc=com \
		LDAP_BASE_DN=dc=redhat,dc=com \
		LDAP_START_TLS=true \
		./bin/ldapcheck $(USER); \
	fi

dev: ## Set up development environment
	@echo "Setting up development environment..."
	go mod tidy
	mkdir -p bin
	@echo "Development environment ready"

# Cleanup commands
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -f bin/ldapcheck
	rm -f coverage.out coverage.html
	rm -rf bin/
	go clean ./...
	@echo "Cleanup completed"

clean-all: clean ## Clean everything including caches
	@echo "Deep cleaning..."
	go clean -cache -testcache -modcache
	@echo "Deep cleanup completed"

# Release commands
release-check: ## Check if ready for release
	@echo "Checking release readiness..."
	@echo "Version: $(shell cat VERSION)"
	@echo "Module: $(shell head -1 go.mod)"
	@echo "Tests: $(shell go test . -v 2>&1 | grep -c '^--- PASS') passing"
	@echo "Dependencies: $(shell go list -m all | wc -l) modules"
	go build .
	go build ./cmd/ldapcheck
	@echo "Release check completed"

tag: ## Create git tag (use: make tag VERSION=v1.0.1)
	@if [ -z "$(VERSION)" ]; then \
		echo "Please specify VERSION: make tag VERSION=v1.0.1"; \
	else \
		echo "Creating tag $(VERSION)..."; \
		git tag -a $(VERSION) -m "Release $(VERSION)"; \
		echo "Tag $(VERSION) created"; \
		echo "Push with: git push origin $(VERSION)"; \
	fi

# Documentation
docs: ## Generate documentation
	@echo "Generating documentation..."
	go doc -all . > docs.txt
	@echo "Documentation generated: docs.txt"

# Environment setup
env-example: ## Show environment variable example
	@echo "Environment Variable Setup:"
	@echo "=============================="
	@cat config.example.env | grep -E "^[A-Z].*=" | head -10
	@echo ""
	@echo "For full examples, see: config.example.env"

# Quick commands
quick: fmt vet test ## Quick development cycle (format, vet, test)
	@echo "Quick development cycle completed"

all: clean install build test cli ## Build everything from scratch
	@echo "Complete build finished!"

# Default target when no arguments
.DEFAULT_GOAL := help
