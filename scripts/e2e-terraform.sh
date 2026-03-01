#!/bin/bash
# e2e-terraform.sh — E2E tests for the Terraform credentials helper
# Assumes isolated environment (HOME, GNUPGHOME, XDG_*) set up by Makefile
set -e

BIN="bin/dotsecenv"
HELPER="contrib/terraform-credentials-dotsecenv"
chmod +x "$BIN" "$HELPER"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

pass() { echo "  PASS: $*"; ((TESTS_PASSED++)) || true; }
fail() { echo "  FAIL: $*"; ((TESTS_FAILED++)) || true; }

echo "==> Generating test key"
"$BIN" identity create --name "TF Test" --email "tf@test" --algo RSA4096 --no-passphrase

echo "==> Initializing vault"
mkdir -p "$XDG_DATA_HOME/dotsecenv"
"$BIN" init config
# Strip config to a single vault so the helper works without -v in non-TTY
sed -i.bak '/^  - .dotsecenv\/vault$/d; /^  - \/var\/lib\/dotsecenv\/vault$/d' "$XDG_CONFIG_HOME/dotsecenv/config"
rm -f "$XDG_CONFIG_HOME/dotsecenv/config.bak"
"$BIN" init vault -v "$XDG_DATA_HOME/dotsecenv/vault"
KEY=$(gpg --list-keys --with-colons tf@test | awk -F: '/^fpr:/{print $10; exit}')
"$BIN" login "$KEY"

echo "==> Testing CLI flags"

# Test 1: --json flag rejects invalid JSON
((TESTS_RUN++)) || true
if echo 'not json' | "$BIN" secret store TF_TEST_INVALID --json 2>&1 | grep -qi "not valid json"; then
    pass "--json rejects invalid JSON"
else
    fail "--json should reject invalid JSON"
fi

# Test 2: --json flag accepts valid JSON
((TESTS_RUN++)) || true
if echo '{"token":"abc123"}' | "$BIN" secret store TF_JSON_TEST --json 2>/dev/null; then
    pass "--json accepts valid JSON"
else
    fail "--json should accept valid JSON"
fi

# Test 3: smart JSON marshaling on get --json
((TESTS_RUN++)) || true
json_output=$("$BIN" secret get TF_JSON_TEST --json 2>/dev/null)
if echo "$json_output" | grep -q '"token"'; then
    pass "smart JSON marshaling embeds raw JSON"
else
    fail "smart JSON marshaling failed, got: $json_output"
fi

# Test 4: --ignore-not-found on secret forget (nonexistent key)
((TESTS_RUN++)) || true
if "$BIN" secret forget NONEXISTENT_KEY --ignore-not-found 2>/dev/null; then
    pass "--ignore-not-found exits 0 for nonexistent key"
else
    fail "--ignore-not-found should exit 0 for nonexistent key"
fi

# Test 5: --ignore-not-found on secret forget (already deleted)
((TESTS_RUN++)) || true
echo "tempval" | "$BIN" secret store TF_DELETE_TEST 2>/dev/null
"$BIN" secret forget TF_DELETE_TEST 2>/dev/null
if "$BIN" secret forget TF_DELETE_TEST --ignore-not-found 2>/dev/null; then
    pass "--ignore-not-found exits 0 for already-deleted key"
else
    fail "--ignore-not-found should exit 0 for already-deleted key"
fi

echo "==> Testing credentials helper wrapper"

# Test 6: store verb
((TESTS_RUN++)) || true
if echo '{"token":"my-tf-token"}' | "$HELPER" store app.terraform.io 2>/dev/null; then
    pass "store verb succeeds"
else
    fail "store verb failed"
fi

# Test 7: get verb returns stored credentials
((TESTS_RUN++)) || true
get_output=$("$HELPER" get app.terraform.io 2>/dev/null)
if echo "$get_output" | grep -q "my-tf-token"; then
    pass "get verb returns stored token"
else
    fail "get verb failed, got: $get_output"
fi

# Test 8: store with extra properties preserves them
((TESTS_RUN++)) || true
echo '{"token":"tok2","extra_prop":"preserved"}' | "$HELPER" store registry.example.com 2>/dev/null
get_output2=$("$HELPER" get registry.example.com 2>/dev/null)
if echo "$get_output2" | grep -q "extra_prop"; then
    pass "store preserves extra properties"
else
    fail "store did not preserve extra properties, got: $get_output2"
fi

# Test 9: forget verb
((TESTS_RUN++)) || true
if "$HELPER" forget app.terraform.io 2>/dev/null; then
    pass "forget verb succeeds"
else
    fail "forget verb failed"
fi

# Test 10: get after forget returns {}
((TESTS_RUN++)) || true
get_after_forget=$("$HELPER" get app.terraform.io 2>/dev/null)
if [ "$get_after_forget" = "{}" ]; then
    pass "get after forget returns {}"
else
    fail "get after forget should return {}, got: $get_after_forget"
fi

# Test 11: forget on nonexistent host exits 0 (idempotent)
((TESTS_RUN++)) || true
if "$HELPER" forget never.stored.host 2>/dev/null; then
    pass "forget on nonexistent host exits 0"
else
    fail "forget on nonexistent host should exit 0"
fi

# Test 12: store rejects non-JSON
((TESTS_RUN++)) || true
if echo 'not json' | "$HELPER" store bad.host 2>/dev/null; then
    fail "store should reject non-JSON"
else
    pass "store rejects non-JSON"
fi

# Test 13: store rejects JSON without token key
((TESTS_RUN++)) || true
if echo '{"nottoken":"value"}' | "$HELPER" store bad.host 2>/dev/null; then
    fail "store should reject JSON without token"
else
    pass "store rejects JSON without token key"
fi

# Test 14: unsupported verb exits non-zero
((TESTS_RUN++)) || true
if "$HELPER" badverb some.host 2>/dev/null; then
    fail "unsupported verb should exit non-zero"
else
    pass "unsupported verb exits non-zero"
fi

# Test 15: get on never-stored host returns {}
((TESTS_RUN++)) || true
get_empty=$("$HELPER" get never.stored.host 2>/dev/null)
if [ "$get_empty" = "{}" ]; then
    pass "get on never-stored host returns {}"
else
    fail "get on never-stored host should return {}, got: $get_empty"
fi

echo ""
echo "==> Terraform credentials helper E2E results"
echo "Tests run:    $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $TESTS_FAILED"

if [ "$TESTS_FAILED" -gt 0 ]; then
    exit 1
fi
echo "==> All tests passed"
