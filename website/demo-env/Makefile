DEMO_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DOTSECENV_BIN := $(DEMO_DIR)../../dotsecenv/bin/dotsecenv
DEMO_MAGIC := $(DEMO_DIR)demos/_demo-magic.sh

# Download demo-magic if not present
$(DEMO_MAGIC):
	curl -sL https://raw.githubusercontent.com/paxtonhare/demo-magic/master/demo-magic.sh -o $@

.PHONY: help
help:
	@echo "Demo environment for recording asciinema demos"
	@echo ""
	@echo "Usage: make demo"
	@echo ""
	@echo "This creates an isolated zsh environment with:"
	@echo "  - Fresh HOME directory (temp)"
	@echo "  - Fresh GNUPGHOME (no existing keys)"
	@echo "  - dotsecenv binary in PATH"
	@echo ""
	@echo "Notes: "
	@echo "  - demo-magic needs pv to run: `brew install pv`"
	@echo ""

.PHONY: usage
usage:
	@echo ""
	@echo "Record a demo with: "
	@echo "  asciinema record demo.cast --title \"DotSecEnv demo\" --idle-time-limit 2 --command 'demos/[NAME].sh'"

# Start isolated zsh environment for recording demos
.PHONY: demo
demo: $(DEMO_MAGIC)
	$(MAKE) -C ../../dotsecenv clean build
	@DEMO_HOME=$$(mktemp -d) && \
	cp $(DEMO_DIR).zshrc "$$DEMO_HOME/.zshrc" && \
	mkdir -p "$$DEMO_HOME/.gnupg" && \
	chmod 700 "$$DEMO_HOME/.gnupg" && \
	cp $(DOTSECENV_BIN) "$$DEMO_HOME/" && \
	cp $(DEMO_DIR)setup-gpg.sh "$$DEMO_HOME/" && \
	chmod +x "$$DEMO_HOME/setup-gpg.sh" && \
	ln -s $(DEMO_DIR)demos "$$DEMO_HOME/demos" && \
	echo "Setting up demo GPG key..." && \
	HOME="$$DEMO_HOME" GNUPGHOME="$$DEMO_HOME/.gnupg" "$$DEMO_HOME/setup-gpg.sh" "$$DEMO_HOME/.gnupg" && \
	echo "" && \
	echo "Installing dotsecenv shell plugin..." && \
	HOME="$$DEMO_HOME" XDG_DATA_HOME="$$DEMO_HOME/.local/share" curl -fsSL https://raw.githubusercontent.com/dotsecenv/plugin/main/install.sh | HOME="$$DEMO_HOME" XDG_DATA_HOME="$$DEMO_HOME/.local/share" bash && \
	echo "Demo shell starting in: $$DEMO_HOME" && \
	$(MAKE) usage && \
	HOME="$$DEMO_HOME" GNUPGHOME="$$DEMO_HOME/.gnupg" zsh -i && \
	echo "Demo shell exited ($$DEMO_HOME)."
