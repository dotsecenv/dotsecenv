# Default target
.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development:"
	@echo "  dev        Start development server at http://localhost:4321"
	@echo "  start      Alias for dev"
	@echo ""
	@echo "Production:"
	@echo "  build      Build for production (output to dist/)"
	@echo "  preview    Preview production build"
	@echo ""
	@echo "Quality:"
	@echo "  lint       Lint MDX files (markdownlint + eslint)"
	@echo ""
	@echo "Assets:"
	@echo "  favicons   Generate favicons from src/assets/logo.png"
	@echo ""
	@echo "Setup & Maintenance:"
	@echo "  install    Install dependencies"
	@echo "  hooks      Install git hooks using lefthook"
	@echo "  clean      Remove build artifacts (dist/)"
	@echo "  distclean  Remove dist/ and node_modules/"

# Development
.PHONY: dev
dev:
	pnpm dev

.PHONY: start
start: dev

# Production build
.PHONY: build
build: favicons
	pnpm build

.PHONY: preview
preview:
	pnpm preview

# Quality
.PHONY: lint
lint:
	pnpm lint

# Assets
.PHONY: favicons
favicons:
	node scripts/generate-favicons.mjs

# Setup & Maintenance
.PHONY: install
install:
	pnpm install --frozen-lockfile

.PHONY: clean
clean:
	rm -rf dist/

.PHONY: distclean
distclean: clean
	rm -rf node_modules/

# Git Hooks
.PHONY: hooks
hooks: install-lefthook
	@echo "Installing git hooks..."
	@$(LEFTHOOK) install

# =============================================================================
# Development Tool Installation
# =============================================================================

GOBIN := $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)

LEFTHOOK := $(GOBIN)/lefthook

.PHONY: install-lefthook
install-lefthook:
	@if ! [ -x "$(LEFTHOOK)" ]; then \
		echo "Installing lefthook..."; \
		go install github.com/evilmartians/lefthook/v2@v2.0.13; \
	fi
