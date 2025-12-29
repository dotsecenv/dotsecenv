.PHONY: help
help:
	@echo "dotsecenv Makefile targets:"
	@echo "  make build          - Build for current OS (auto-detect)"
	@echo "  make build-linux    - Build for Linux with BoringCrypto (FIPS)"
	@echo "  make build-darwin   - Build for macOS (standard crypto)"
	@echo "  make test           - Run tests"
	@echo "  make test-race      - Run tests with race condition detection"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make vet            - Run go vet"
	@echo "  make lint           - Run linting (vet + fmt check)"
	@echo "  make man            - Generate man pages"
	@echo "  make docs           - Generate markdown documentation"
	@echo "  make completions    - Generate shell completions"

.PHONY: all
all: clean build lint test test-race e2e update completions docs man

# Common ldflags for version info
LDFLAGS := -X main.version=$$(git describe --tags --always --dirty) -X main.commit=$$(git rev-parse --short HEAD) -X main.date=$$(date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: clean
clean:
	@rm -rf bin/ build/ dist/ docs/ man/ completions/
	echo "Reinitializing dotsecenv vault..."
	go clean -testcache
	
# Auto-detect OS and dispatch to platform-specific target
.PHONY: build
build:
ifeq ($(shell uname -s),Linux)
	@$(MAKE) build-linux
else ifeq ($(shell uname -s),Darwin)
	@$(MAKE) build-darwin
else
	@echo "Unsupported OS: $$(uname -s). Use build-linux or build-darwin explicitly."
	@exit 1
endif

# Linux: BoringCrypto for FIPS-approved cryptography (requires CGO)
.PHONY: build-linux
build-linux:
	@echo "Building dotsecenv for Linux with BoringCrypto (FIPS-approved)..."
	CGO_ENABLED=1 GOEXPERIMENT=boringcrypto go build -ldflags "$(LDFLAGS)" -o bin/dotsecenv ./cmd/dotsecenv
	@echo "Binary built at: bin/dotsecenv"

# macOS: Standard crypto (BoringCrypto not available on Darwin)
.PHONY: build-darwin
build-darwin:
	@echo "Building dotsecenv for macOS (standard crypto)..."
	CGO_ENABLED=0 go build -ldflags "-s -w $(LDFLAGS)" -o bin/dotsecenv ./cmd/dotsecenv
	@echo "Binary built at: bin/dotsecenv"

GOLANGCI_LINT_VERSION := latest
GOLANGCI_LINT := $(shell go env GOPATH)/bin/golangci-lint

.PHONY: install-lint
install-lint:
	@if ! [ -x "$(GOLANGCI_LINT)" ]; then \
		echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin $(GOLANGCI_LINT_VERSION); \
	fi

.PHONY: lint
lint: install-lint
	@echo "Running go mod tidy..."
	@go mod tidy
	@echo "Checking code formatting..."
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "Go code is not formatted:"; \
		gofmt -l .; \
		exit 1; \
	fi
	@echo "Running golangci-lint..."
	@$(GOLANGCI_LINT) run ./...

.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...

.PHONY: test-race
test-race:
	@echo "Running tests with race condition detection..."
	@go test -race -v ./...

.PHONY: e2e
e2e: build
	@./scripts/e2e.sh $(E2E_FLAGS)

.PHONY: update
update:
	@echo "Updating dependencies..."
	@go get -u ./...

.PHONY: completions
completions: build
	@echo "Generating shell completions..."
	@mkdir -p completions
	@bin/dotsecenv completion bash > completions/dotsecenv.bash
	@bin/dotsecenv completion zsh > completions/dotsecenv.zsh
	@bin/dotsecenv completion fish > completions/dotsecenv.fish

.PHONY: docs
docs:
	@echo "Generating markdown documentation..."
	@go run -tags gendocs ./cmd/dotsecenv markdown -o docs/cli

.PHONY: man
man:
	@echo "Generating man pages..."
	@go run -tags gendocs ./cmd/dotsecenv -o man/man1
