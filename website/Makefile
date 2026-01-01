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
