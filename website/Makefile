.PHONY: help install dev start build preview clean distclean favicons

# Default target
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
	@echo "Assets:"
	@echo "  favicons   Generate favicons from src/assets/logo.png"
	@echo ""
	@echo "Setup & Maintenance:"
	@echo "  install    Install dependencies"
	@echo "  clean      Remove build artifacts (dist/)"
	@echo "  distclean  Remove dist/ and node_modules/"

# Development
dev:
	pnpm dev

start: dev

# Production build
build:
	pnpm build

preview:
	pnpm preview

# Assets
favicons:
	node scripts/generate-favicons.mjs

# Setup & Maintenance
install:
	pnpm install

clean:
	rm -rf dist/

distclean: clean
	rm -rf node_modules/
