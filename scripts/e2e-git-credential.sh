#!/bin/bash
# e2e-git-credential.sh — E2E tests for the git credential helper
# Assumes isolated environment (HOME, GNUPGHOME, XDG_*) set up by Makefile
set -e

BIN="bin/dotsecenv"
HELPER="contrib/git-credential-dotsecenv"
chmod +x "$BIN" "$HELPER"

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required for the git credential helper e2e tests" >&2
    exit 1
fi

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

pass() { echo "  PASS: $*"; ((TESTS_PASSED++)) || true; }
fail() { echo "  FAIL: $*"; ((TESTS_FAILED++)) || true; }

echo "==> Generating test key"
"$BIN" identity create --name "Git Cred Test" --email "git@test" --algo RSA4096 --no-passphrase

echo "==> Initializing vault"
mkdir -p "$XDG_DATA_HOME/dotsecenv"
"$BIN" init config
# Strip config to a single vault so the helper works without -v in non-TTY
sed -i.bak '/^  - .dotsecenv\/vault$/d; /^  - \/var\/lib\/dotsecenv\/vault$/d' "$XDG_CONFIG_HOME/dotsecenv/config"
rm -f "$XDG_CONFIG_HOME/dotsecenv/config.bak"
"$BIN" init vault -v "$XDG_DATA_HOME/dotsecenv/vault"
KEY=$(gpg --list-keys --with-colons git@test | awk -F: '/^fpr:/{print $10; exit}')
"$BIN" login "$KEY"

echo "==> Testing git credential helper"

# Test 1: store then get round-trips username + password through the JSON layer
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=gitlab.com\nusername=me\npassword=glpat-xxx\n\n' | "$HELPER" store 2>/dev/null
get_out=$(printf 'protocol=https\nhost=gitlab.com\n\n' | "$HELPER" get 2>/dev/null)
if echo "$get_out" | grep -q '^username=me$' && echo "$get_out" | grep -q '^password=glpat-xxx$'; then
    pass "store then get round-trips username + password"
else
    fail "store/get round-trip failed, got: $get_out"
fi

# Test 2: get on a never-stored host prints nothing and exits 0
((TESTS_RUN++)) || true
get_out=$(printf 'protocol=https\nhost=never.stored.example\n\n' | "$HELPER" get 2>/dev/null); rc=$?
if [ -z "$get_out" ] && [ "$rc" -eq 0 ]; then
    pass "get on never-stored host is empty, exit 0"
else
    fail "get on never-stored host should be empty/exit0, got: '$get_out' rc=$rc"
fi

# Test 3: get degrades to empty/exit 0 when the environment has no login/config
((TESTS_RUN++)) || true
brokencfg=$(mktemp -d)
get_out=$(printf 'protocol=https\nhost=gitlab.com\n\n' | XDG_CONFIG_HOME="$brokencfg" XDG_DATA_HOME="$brokencfg" "$HELPER" get 2>/dev/null); rc=$?
if [ -z "$get_out" ] && [ "$rc" -eq 0 ]; then
    pass "get with no login/config degrades to empty, exit 0"
else
    fail "get should degrade to empty/exit0, got: '$get_out' rc=$rc"
fi
rm -rf "$brokencfg"

# Test 4: erase then get returns empty
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=gitlab.com\n\n' | "$HELPER" erase 2>/dev/null
get_out=$(printf 'protocol=https\nhost=gitlab.com\n\n' | "$HELPER" get 2>/dev/null)
if [ -z "$get_out" ]; then
    pass "erase then get returns empty"
else
    fail "get after erase should be empty, got: $get_out"
fi

# Test 5: erase on a never-stored host exits 0 (idempotent)
((TESTS_RUN++)) || true
if printf 'protocol=https\nhost=never.stored.example\n\n' | "$HELPER" erase 2>/dev/null; then
    pass "erase on never-stored host exits 0"
else
    fail "erase on never-stored host should exit 0"
fi

# Test 6: hyphenated host round-trips (proves _DASH_ / _DOT_ encoding)
((TESTS_RUN++)) || true
h="git-codecommit.us-east-1.amazonaws.com"
printf 'protocol=https\nhost=%s\nusername=u\npassword=p6\n\n' "$h" | "$HELPER" store 2>/dev/null
get_out=$(printf 'protocol=https\nhost=%s\n\n' "$h" | "$HELPER" get 2>/dev/null)
if echo "$get_out" | grep -q '^password=p6$'; then
    pass "hyphenated host round-trips"
else
    fail "hyphenated host failed, got: $get_out"
fi

# Test 7: host with port round-trips (proves _COLON_ encoding)
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=example.com:8080\nusername=u\npassword=p7\n\n' | "$HELPER" store 2>/dev/null
get_out=$(printf 'protocol=https\nhost=example.com:8080\n\n' | "$HELPER" get 2>/dev/null)
if echo "$get_out" | grep -q '^password=p7$'; then
    pass "host with port round-trips"
else
    fail "host with port failed, got: $get_out"
fi

# Test 8: IP-address host round-trips (proves protocol prefix + dot-free encoding)
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=192.168.1.1\nusername=u\npassword=p8\n\n' | "$HELPER" store 2>/dev/null
get_out=$(printf 'protocol=https\nhost=192.168.1.1\n\n' | "$HELPER" get 2>/dev/null)
if echo "$get_out" | grep -q '^password=p8$'; then
    pass "IP-address host round-trips"
else
    fail "IP-address host failed, got: $get_out"
fi

# Test 9: OAuth fields are preserved (Mode 2 contract)
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=oauth.example\nusername=oauth2\npassword=at123\npassword_expiry_utc=1799999999\noauth_refresh_token=rt456\n\n' | "$HELPER" store 2>/dev/null
get_out=$(printf 'protocol=https\nhost=oauth.example\n\n' | "$HELPER" get 2>/dev/null)
if echo "$get_out" | grep -q '^oauth_refresh_token=rt456$' && echo "$get_out" | grep -q '^password_expiry_utc=1799999999$'; then
    pass "OAuth refresh token + expiry preserved"
else
    fail "OAuth fields not preserved, got: $get_out"
fi

# Test 10: stored secret names are dot-free (encoded)
((TESTS_RUN++)) || true
key_list=$("$BIN" secret get 2>/dev/null || true)
if echo "$key_list" | grep -qi 'HTTPS_SLASH_GITLAB_DOT_COM' && ! echo "$key_list" | grep -qi 'GITLAB\.COM'; then
    pass "secret names are dot-free (encoded)"
else
    fail "expected encoded dot-free key, got keys: $key_list"
fi

# Test 11: store with no credential fields (host only) stores nothing, exit 0
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=empty.example\n\n' | "$HELPER" store 2>/dev/null; rc=$?
get_out=$(printf 'protocol=https\nhost=empty.example\n\n' | "$HELPER" get 2>/dev/null)
if [ "$rc" -eq 0 ] && [ -z "$get_out" ]; then
    pass "store with no fields stores nothing, exit 0"
else
    fail "empty store should be a no-op, rc=$rc get='$get_out'"
fi

# Test 12: unsupported operation exits non-zero
((TESTS_RUN++)) || true
if printf 'protocol=https\nhost=gitlab.com\n\n' | "$HELPER" bogus 2>/dev/null; then
    fail "unsupported operation should exit non-zero"
else
    pass "unsupported operation exits non-zero"
fi

echo ""
echo "==> Git credential helper E2E results"
echo "Tests run:    $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $TESTS_FAILED"

if [ "$TESTS_FAILED" -gt 0 ]; then
    exit 1
fi
echo "==> All tests passed"
