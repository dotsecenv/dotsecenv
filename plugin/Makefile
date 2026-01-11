.PHONY: help
help:
	@echo "shell targets:"
	@echo "  make test-plugins         - Run unit tests (bash/zsh/fish)"
	@echo "  make test-bash            - Run bash unit tests"
	@echo "  make test-zsh             - Run zsh unit tests"
	@echo "  make test-fish            - Run fish unit tests"
	@echo "  make test-managers        - Run plugin manager integration tests (Docker, local)"
	@echo "  make test-managers-remote - Run plugin manager e2e tests from GitHub (Docker)"
	@echo "  make fmt                  - Format all shell scripts"
	@echo "  make fmt-check            - Check formatting without modifying files"
	@echo "  make lint                 - Lint shell plugin scripts"
	@echo "  make hooks                - Install git hooks using lefthook"
	@echo "  make install-tools        - Install all dev tools"

.PHONY: test-plugins
test-plugins: test-bash test-zsh test-fish
	@echo "All tests passed!"

.PHONY: test-bash
test-bash:
	@echo "Running bash plugin tests..."
	@./tests/test_plugins.sh --bash-only

.PHONY: test-zsh
test-zsh:
	@echo "Running zsh plugin tests..."
	@./tests/test_plugins.sh --zsh-only

.PHONY: test-fish
test-fish:
	@echo "Running fish shell plugin tests..."
	@fish ./tests/test_plugins.fish

.PHONY: test-managers
test-managers:
	@echo "Running plugin manager integration tests (local)..."
	@./tests/test_plugin_managers.sh

.PHONY: test-managers-remote
test-managers-remote:
	@echo "Running plugin manager integration tests (remote)..."
	@./tests/test_plugin_managers.sh --remote

.PHONY: test-manager-ohmyzsh
test-manager-ohmyzsh:
	@./tests/test_plugin_managers.sh --manager=ohmyzsh

.PHONY: test-manager-zinit
test-manager-zinit:
	@./tests/test_plugin_managers.sh --manager=zinit

.PHONY: test-manager-antidote
test-manager-antidote:
	@./tests/test_plugin_managers.sh --manager=antidote

.PHONY: test-manager-ohmybash
test-manager-ohmybash:
	@./tests/test_plugin_managers.sh --manager=ohmybash

.PHONY: test-manager-fisher
test-manager-fisher:
	@./tests/test_plugin_managers.sh --manager=fisher

.PHONY: test-manager-ohmyfish
test-manager-ohmyfish:
	@./tests/test_plugin_managers.sh --manager=ohmyfish

.PHONY: lint
lint:
	@echo "Checking shell scripts..."
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck shell/*.sh shell/*.bash 2>/dev/null || true; \
	else \
		echo "shellcheck not found, skipping shell linting"; \
	fi
	@if command -v fish >/dev/null 2>&1; then \
		fish -n shell/*.fish shell/functions/*.fish shell/conf.d/*.fish 2>/dev/null || true; \
	else \
		echo "fish not found, skipping fish syntax check"; \
	fi

# Shell script files to format
SHELL_FILES := ./_dotsecenv_core.sh ./dotsecenv.plugin.bash ./dotsecenv.plugin.zsh \
               ./tests/test_plugins.sh ./tests/test_plugin_managers.sh ./install.sh
FISH_FILES := ./conf.d/dotsecenv.fish ./tests/test_plugins.fish

.PHONY: fmt
fmt: install-shfmt
	@echo "Formatting shell scripts..."
	shfmt -w -i 4 $(SHELL_FILES)
	@echo "Formatting fish scripts..."
	fish_indent -w $(FISH_FILES)
	@echo "Done!"

.PHONY: fmt-check
fmt-check: install-shfmt
	@echo "Checking shell script formatting..."
	@shfmt -d -i 4 $(SHELL_FILES)
	@echo "Checking fish script formatting..."
	@for f in $(FISH_FILES); do \
		fish_indent "$$f" | diff -q "$$f" - > /dev/null 2>&1 || { echo "$$f is not formatted correctly"; exit 1; }; \
	done
	@echo "All files formatted correctly!"

.PHONY: hooks
hooks: install-lefthook
	@echo "Installing git hooks..."
	@$(LEFTHOOK) install

# =============================================================================
# Development Tool Installation
# =============================================================================

.PHONY: install-tools
install-tools: install-lefthook install-shfmt

GOBIN := $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)

LEFTHOOK := $(GOBIN)/lefthook

.PHONY: install-lefthook
install-lefthook:
	@if ! [ -x "$(LEFTHOOK)" ]; then \
		echo "Installing lefthook..."; \
		go install github.com/evilmartians/lefthook/v2@v2.0.13; \
	fi

SHFMT := $(GOBIN)/shfmt

.PHONY: install-shfmt
install-shfmt:
	@if ! [ -x "$(SHFMT)" ]; then \
		echo "Installing shfmt..."; \
		go install mvdan.cc/sh/v3/cmd/shfmt@latest; \
	fi
