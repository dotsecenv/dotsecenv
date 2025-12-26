#!/usr/bin/env bash

# Automated asciinema demo using demo-magic
# https://github.com/paxtonhare/demo-magic

# shellcheck source=/dev/null
source ~/demos/_demo-magic.sh
source "$XDG_DATA_HOME/dotsecenv/dotsecenv.plugin.bash"

# Configure demo-magic (used by sourced script)
# shellcheck disable=SC2034
TYPE_SPEED=25
# shellcheck disable=SC2034
DEMO_PROMPT="❯ "
# shellcheck disable=SC2034
DEMO_CMD_COLOR="$GREEN"
# shellcheck disable=SC2034
DEMO_COMMENT_COLOR="$GREY"

# shellcheck disable=SC2034
NO_WAIT=true
# shellcheck disable=SC2034
PROMPT_TIMEOUT=1

# Extract key ID (do this silently before the demo starts)
KEY_ID=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')

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
pe "echo \"my-database-password\" | dotsecenv secret put DATABASE_PASSWORD"

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
p "# Done! 🎉"
