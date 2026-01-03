.PHONY: help
help:
	@echo "dotsecenv Makefile targets:"
	@echo "  make all            - Run all targets"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make update         - Update go dependencies"
	@echo "  make build          - Build with FIPS 140-3 crypto (no CGO)"
	@echo "  make lint           - Run linting (vet + fmt check)"
	@echo "  make test           - Run tests"
	@echo "  make test-race      - Run tests with race condition detection"
	@echo "  make e2e            - Run end-to-end tests using the compiled binary"
	@echo "  make completions    - Generate shell completions"
	@echo "  make docs           - Generate markdown documentation"
	@echo "  make man            - Generate man pages"
	@echo "  make hooks          - Install git hooks using lefthook"
	@echo "  make release-test   - Test release build (snapshot)"
	@echo "  make install-tools  - Install all dev tools"

.PHONY: all
all: clean update build lint test test-race e2e completions docs man

# Common ldflags for version info
LDFLAGS := -X main.version=$$(git describe --tags --always --dirty) -X main.commit=$$(git rev-parse --short HEAD) -X main.date=$$(date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: clean
clean:
	@rm -rf bin/ build/ dist/ docs/ man/ completions/
	echo "Reinitializing dotsecenv vault..."
	go clean -testcache
	
# Build with Go's native FIPS 140-3 module (no CGO required)
# See: https://go.dev/blog/fips140
.PHONY: build
build:
	@echo "Building dotsecenv with FIPS 140-3 crypto..."
	CGO_ENABLED=0 GOFIPS140=v1.0.0 go build -ldflags "-s -w $(LDFLAGS)" -o bin/dotsecenv ./cmd/dotsecenv
	@echo "Binary built at: bin/dotsecenv"

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
	go test -v -p 1 ./...

.PHONY: test-race
test-race:
	@echo "Running tests with race condition detection..."
	go test -race -v -p 1 ./...

.PHONY: e2e
e2e: build
	@E2E_HOME=$$(mktemp -d) && \
	mkdir -p "$$E2E_HOME/.gnupg" "$$E2E_HOME/.config" "$$E2E_HOME/.local/share" && \
	chmod 700 "$$E2E_HOME/.gnupg" && \
	cp bin/dotsecenv "$$E2E_HOME/" && \
	echo "Running e2e tests in isolated environment: $$E2E_HOME" && \
	HOME="$$E2E_HOME" \
	PATH="$$E2E_HOME:$$PATH" \
	GNUPGHOME="$$E2E_HOME/.gnupg" \
	XDG_CONFIG_HOME="$$E2E_HOME/.config" \
	XDG_DATA_HOME="$$E2E_HOME/.local/share" \
	./scripts/e2e.sh $(E2E_FLAGS) && \
	rm -rf "$$E2E_HOME" && \
	echo "Cleaned up $$E2E_HOME"

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
	@bin/dotsecenv completion powershell > completions/dotsecenv.ps1

.PHONY: docs
docs:
	@echo "Generating markdown documentation..."
	@go run -tags gendocs ./cmd/dotsecenv markdown -o docs/cli

.PHONY: man
man:
	@echo "Generating man pages..."
	@go run -tags gendocs ./cmd/dotsecenv -o man/man1

.PHONY: hooks
hooks: install-lefthook
	@echo "Installing git hooks..."
	@$(LEFTHOOK) install

.PHONY: release-test
release-test: install-goreleaser install-syft
	@echo "Testing release build..."
	@$(GORELEASER) release --snapshot --clean --skip=sign,publish,nfpm

# =============================================================================
# Development Tool Installation
# =============================================================================

GOBIN := $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)

.PHONY: install-tools
install-tools: install-lefthook install-lint install-syft install-goreleaser

LEFTHOOK := $(GOBIN)/lefthook

.PHONY: install-lefthook
install-lefthook:
	@if ! [ -x "$(LEFTHOOK)" ]; then \
		echo "Installing lefthook..."; \
		go install github.com/evilmartians/lefthook/v2@v2.0.13; \
	fi

GOLANGCI_LINT_VERSION := latest
GOLANGCI_LINT := $(GOBIN)/golangci-lint

.PHONY: install-lint
install-lint:
	@if ! [ -x "$(GOLANGCI_LINT)" ]; then \
		echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $${GOBIN:-$$(go env GOPATH)/bin} $(GOLANGCI_LINT_VERSION); \
	fi

SYFT := $(GOBIN)/syft

.PHONY: install-syft
install-syft:
	@if ! [ -x "$(SYFT)" ]; then \
		echo "Installing syft..."; \
		curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b $${GOBIN:-$$(go env GOPATH)/bin}; \
	fi

GORELEASER := $(GOBIN)/goreleaser

.PHONY: install-goreleaser
install-goreleaser:
	@if ! [ -x "$(GORELEASER)" ]; then \
		echo "Installing goreleaser..."; \
		go install github.com/goreleaser/goreleaser/v2@latest; \
	fi
