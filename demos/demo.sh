#!/usr/bin/env bash
#
# demo.sh - Automated asciinema demo using demo-magic
#
# This script is designed to run inside a sandbox environment created by:
#   make demo
#
# The sandbox provides:
# - Isolated HOME with GPG keys
# - dotsecenv binary in PATH
# - Shell plugin loaded
#
# Dependencies:
# - demo-magic (downloaded automatically by Makefile)
# - asciinema (for recording)
#
# https://github.com/paxtonhare/demo-magic

set -e

# Source demo-magic (must be in $HOME/demos/)
if [[ ! -f ~/demos/_demo-magic.sh ]]; then
    echo "ERROR: demo-magic not found at ~/demos/_demo-magic.sh"
    echo "Run 'make demo' from the dotsecenv directory to set up the environment."
    exit 1
fi

# shellcheck source=/dev/null
source ~/demos/_demo-magic.sh

# Source dotsecenv plugin for shell integration demo
if [[ -f "$XDG_DATA_HOME/dotsecenv/dotsecenv.plugin.bash" ]]; then
    # shellcheck source=/dev/null
    source "$XDG_DATA_HOME/dotsecenv/dotsecenv.plugin.bash"
fi

# Configure demo-magic (used by sourced script)
# shellcheck disable=SC2034
TYPE_SPEED=25
# shellcheck disable=SC2034
DEMO_PROMPT="❯ "
# shellcheck disable=SC2034
DEMO_CMD_COLOR="$GREEN"
# shellcheck disable=SC2034
DEMO_COMMENT_COLOR="$GREY"

# Auto-advance settings
# shellcheck disable=SC2034
NO_WAIT=true
# shellcheck disable=SC2034
PROMPT_TIMEOUT=1

# Extract default GPG key (do this silently before the demo starts)
KEY_ID="${DEFAULT_GPG_KEY:-$(gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')}"

clear

# Print gpg key info
p "# We created a demo GPG key earlier."
pe "gpg --list-keys --keyid-format long | tail -n +3"

# Configure dotsecenv
p "# Initialize dotsecenv (this is only needed once)"
pe "dotsecenv init config"
pe "dotsecenv init vault"
pe "dotsecenv login $KEY_ID"

p ""
p "# 1. Create your first secret"
pe "echo \"my-database-password\" | dotsecenv secret store DATABASE_PASSWORD"

p ""
p "# 2. You can now decrypt the secret, on demand"
pe "dotsecenv secret get DATABASE_PASSWORD"

p "# This is technically the crux of dotsecenv, but let's see how it can help manage secrets for your projects."
p ""
p "# 3. Define a .secenv file just like you would a .env file, but with a placeholder instead of the actual secret"
pe "echo 'DATABASE_PASSWORD={dotsecenv}' > .secenv"

p ""
p "# Since we have previously installed the shell plugin from <https://github.com/dotsecenv/plugin>,"
p "# cd-ing into a directory with a .secenv file will use dotsecenv to define the env secret automatically."
pe "cd ."
p "# DATABASE_PASSWORD is now available as an env var:"
pe "echo \$DATABASE_PASSWORD"

p ""
p "# Done!"
