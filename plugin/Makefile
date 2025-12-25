.PHONY: help
help:
	@echo "shell targets:"
	@echo "  make test            - Run unit tests (bash/zsh/fish)"
	@echo "  make test-bash-zsh   - Run bash/zsh unit tests"
	@echo "  make test-fish       - Run fish unit tests"
	@echo "  make test-managers   - Run plugin manager integration tests (Docker)"
	@echo "  make test-all        - Run all tests including integration"
	@echo "  make fmt             - Format all shell scripts"
	@echo "  make fmt-check       - Check formatting without modifying files"
	@echo "  make lint            - Lint shell plugin scripts"

.PHONY: test
test: test-bash-zsh test-fish
	@echo "All tests passed!"

.PHONY: test-bash-zsh
test-bash-zsh:
	@echo "Running shell plugin tests..."
	@./tests/test_plugins.sh

.PHONY: test-fish
test-fish:
	@echo "Running fish shell plugin tests..."
	@fish ./tests/test_plugins.fish

.PHONY: test-managers
test-managers:
	@echo "Running plugin manager integration tests..."
	@./tests/test_plugin_managers.sh

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

.PHONY: test-all
test-all: test test-managers
	@echo "All tests (unit + integration) passed!"

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

.PHONY: fmt-install
fmt-install:
	@echo "Installing formatters..."
	@if ! command -v shfmt >/dev/null 2>&1; then \
		echo "Installing shfmt..."; \
		if command -v brew >/dev/null 2>&1; then \
			brew install shfmt; \
		elif command -v go >/dev/null 2>&1; then \
			go install mvdan.cc/sh/v3/cmd/shfmt@latest; \
		else \
			curl -sS https://webi.sh/shfmt | sh; \
		fi; \
	else \
		echo "shfmt already installed"; \
	fi
	@if ! command -v fish >/dev/null 2>&1; then \
		echo "Installing fish (for fish_indent)..."; \
		if command -v brew >/dev/null 2>&1; then \
			brew install fish; \
		elif command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y fish; \
		else \
			echo "Please install fish manually: https://fishshell.com"; \
			exit 1; \
		fi; \
	else \
		echo "fish already installed"; \
	fi

.PHONY: fmt
fmt: fmt-install
	@echo "Formatting shell scripts..."
	shfmt -w -i 4 $(SHELL_FILES)
	@echo "Formatting fish scripts..."
	fish_indent -w $(FISH_FILES)
	@echo "Done!"

.PHONY: fmt-check
fmt-check:
	@echo "Checking shell script formatting..."
	@shfmt -d -i 4 $(SHELL_FILES)
	@echo "Checking fish script formatting..."
	@for f in $(FISH_FILES); do \
		fish_indent "$$f" | diff -q "$$f" - > /dev/null 2>&1 || { echo "$$f is not formatted correctly"; exit 1; }; \
	done
	@echo "All files formatted correctly!"
