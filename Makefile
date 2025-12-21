.PHONY: help
help:
	@echo "dotsecenv Makefile targets:"
	@echo "  make build          - Build the dotsecenv binary"
	@echo "  make test           - Run tests"
	@echo "  make test-race      - Run tests with race condition detection"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make vet            - Run go vet"
	@echo "  make lint           - Run linting (vet + fmt check)"
	@echo "  make man            - Generate man pages"
	@echo "  make docs           - Generate markdown documentation"
	@echo "  make completions    - Generate shell completions"

.PHONY: all
all: clean update lint build test test-race man docs completions init e2e validate

.PHONY: build
build:
	@echo "Building dotsecenv..."
	@go build -ldflags "-X main.version=$$(git describe --tags --always --dirty) -X main.commit=$$(git rev-parse --short HEAD) -X main.date=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o bin/dotsecenv ./cmd/dotsecenv
	@echo "Binary built at: bin/dotsecenv"

.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...

.PHONY: test-race
test-race:
	@echo "Running tests with race condition detection..."
	@go test -race -v ./...

.PHONY: clean
clean:
	@rm -rf bin/ build/ dist/ docs/ man/ completions/
	echo "Reinitializing dotsecenv vault..."
	rm -f ~/.config/dotsecenv/config ~/.local/share/dotsecenv/vault .dotsecenv/vault
	go clean -testcache

.PHONY: init
init: clean build
	echo "Reinitializing dotsecenv vault..."
	mkdir -p ~/.local/share/dotsecenv .dotsecenv
	bin/dotsecenv init config
	bin/dotsecenv init vault -v .dotsecenv/vault
	bin/dotsecenv init vault -v ~/.local/share/dotsecenv/vault
	
.PHONY: e2e
e2e: build
	@./scripts/e2e.sh $(E2E_FLAGS)

.PHONY: validate
validate: build
	@echo "Validating vault integrity..."
	@bin/dotsecenv validate

.PHONY: update
update:
	@echo "Updating dependencies..."
	@go get -u ./...

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

.PHONY: man
man:
	@echo "Generating man pages..."
	@go run -tags gendocs ./cmd/dotsecenv -o man/man1

.PHONY: docs
docs:
	@echo "Generating markdown documentation..."
	@go run -tags gendocs ./cmd/dotsecenv markdown -o docs/cli

.PHONY: completions
completions: build
	@echo "Generating shell completions..."
	@mkdir -p completions
	@bin/dotsecenv completion bash > completions/dotsecenv.bash
	@bin/dotsecenv completion zsh > completions/dotsecenv.zsh
	@bin/dotsecenv completion fish > completions/dotsecenv.fish
