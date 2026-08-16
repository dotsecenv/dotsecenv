#!/bin/bash
# e2e-git-credential.sh — E2E tests for the git credential helper
# Assumes isolated environment (HOME, GNUPGHOME, XDG_*) set up by Makefile
set -e

BIN="bin/dotsecenv"
HELPER="contrib/git-credential-dotsecenv"
chmod +x "$BIN" "$HELPER"

# The helper reads credential.dotsecenv.useUsername through git. HOME and
# XDG_CONFIG_HOME are already isolated by the Makefile; this closes the last
# door, so a machine-wide /etc/gitconfig cannot change what the tests see.
export GIT_CONFIG_NOSYSTEM=1

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
# Keep the config exactly as `init config` writes it (repo-local
# .dotsecenv/vault first, then the home vault): the helper leans on dotsecenv's
# own vault resolution, and test 13 exercises the repo-vault half of it.
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
rc=0
get_out=$(printf 'protocol=https\nhost=never.stored.example\n\n' | "$HELPER" get 2>/dev/null) || rc=$?
if [ -z "$get_out" ] && [ "$rc" -eq 0 ]; then
    pass "get on never-stored host is empty, exit 0"
else
    fail "get on never-stored host should be empty/exit0, got: '$get_out' rc=$rc"
fi

# Test 3: get degrades to empty/exit 0 when the environment has no login/config
((TESTS_RUN++)) || true
brokencfg=$(mktemp -d)
rc=0
get_out=$(printf 'protocol=https\nhost=gitlab.com\n\n' | XDG_CONFIG_HOME="$brokencfg" XDG_DATA_HOME="$brokencfg" "$HELPER" get 2>/dev/null) || rc=$?
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
rc=0
printf 'protocol=https\nhost=empty.example\n\n' | "$HELPER" store 2>/dev/null || rc=$?
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

# Test 13: a repo-local committed vault is a first-class store target, by
# design. Vault selection is dotsecenv's: with DOTSECENV_CONFIG pointing at a
# config that resolves only the repo vault, the credential lands encrypted in
# the repo's own .dotsecenv/vault and erase works the same way. (With several
# resolvable vaults, store/erase use dotsecenv's interactive picker — not
# testable without a TTY, and covered by the CLI's own tests.)
((TESTS_RUN++)) || true
proj="$PWD/projrepo"
mkdir -p "$proj"
(cd "$proj" && "$OLDPWD/$BIN" init vault -v .dotsecenv/vault >/dev/null 2>&1)
altcfg="$PWD/git-credentials-config"
DOTSECENV_CONFIG="$altcfg" "$BIN" init config >/dev/null 2>&1
grep -Fv "$XDG_DATA_HOME/dotsecenv/vault" "$altcfg" > "$altcfg.tmp" && mv "$altcfg.tmp" "$altcfg"
(cd "$proj" && DOTSECENV_CONFIG="$altcfg" "$OLDPWD/$BIN" login "$KEY" >/dev/null 2>&1)
h="proj.example"
store_rc=0
(cd "$proj" && printf 'protocol=https\nhost=%s\nusername=me\npassword=pv-1\n\n' "$h" \
    | DOTSECENV_CONFIG="$altcfg" "$OLDPWD/$HELPER" store) >/dev/null 2>&1 || store_rc=$?
proj_get=$(cd "$proj" && printf 'protocol=https\nhost=%s\n\n' "$h" | DOTSECENV_CONFIG="$altcfg" "$OLDPWD/$HELPER" get 2>/dev/null || true)
in_repo_vault=0
grep -q 'HTTPS_SLASH_PROJ' "$proj/.dotsecenv/vault" 2>/dev/null && in_repo_vault=1
erase_rc=0
(cd "$proj" && printf 'protocol=https\nhost=%s\n\n' "$h" | DOTSECENV_CONFIG="$altcfg" "$OLDPWD/$HELPER" erase) >/dev/null 2>&1 || erase_rc=$?
after_erase=$(cd "$proj" && printf 'protocol=https\nhost=%s\n\n' "$h" | DOTSECENV_CONFIG="$altcfg" "$OLDPWD/$HELPER" get 2>/dev/null || true)
if [ "$store_rc" -eq 0 ] && echo "$proj_get" | grep -q 'password=pv-1' \
    && [ "$in_repo_vault" -eq 1 ] && [ "$erase_rc" -eq 0 ] && [ -z "$after_erase" ]; then
    pass "repo-local vault is the store target via DOTSECENV_CONFIG"
else
    fail "repo-vault workflow failed: store_rc=$store_rc get='$proj_get' in_repo_vault=$in_repo_vault erase_rc=$erase_rc after_erase='$after_erase'"
fi

# Test 14: runs of underscores stay distinct. The encoder used to collapse three
# or more underscores into two, so a_-b, a__-b and a___-b all shared one key and
# overwrote each other. Escaping '_' first keeps them apart.
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=a_-b.example\nusername=u\npassword=p14a\n\n' | "$HELPER" store 2>/dev/null
printf 'protocol=https\nhost=a__-b.example\nusername=u\npassword=p14b\n\n' | "$HELPER" store 2>/dev/null
printf 'protocol=https\nhost=a___-b.example\nusername=u\npassword=p14c\n\n' | "$HELPER" store 2>/dev/null
run_a=$(printf 'protocol=https\nhost=a_-b.example\n\n' | "$HELPER" get 2>/dev/null)
run_b=$(printf 'protocol=https\nhost=a__-b.example\n\n' | "$HELPER" get 2>/dev/null)
run_c=$(printf 'protocol=https\nhost=a___-b.example\n\n' | "$HELPER" get 2>/dev/null)
if echo "$run_a" | grep -q '^password=p14a$' && echo "$run_b" | grep -q '^password=p14b$' \
    && echo "$run_c" | grep -q '^password=p14c$'; then
    pass "underscore runs keep separate keys"
else
    fail "underscore runs collided: one='$run_a' two='$run_b' three='$run_c'"
fi

# Test 15: a trailing underscore is part of the name. It used to be stripped, so
# c.example_ landed on c.example's key and served that host's credential.
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=c.example\nusername=u\npassword=p15a\n\n' | "$HELPER" store 2>/dev/null
printf 'protocol=https\nhost=c.example_\nusername=u\npassword=p15b\n\n' | "$HELPER" store 2>/dev/null
tail_plain=$(printf 'protocol=https\nhost=c.example\n\n' | "$HELPER" get 2>/dev/null)
tail_under=$(printf 'protocol=https\nhost=c.example_\n\n' | "$HELPER" get 2>/dev/null)
if echo "$tail_plain" | grep -q '^password=p15a$' && echo "$tail_under" | grep -q '^password=p15b$'; then
    pass "trailing underscore keeps a separate key"
else
    fail "trailing underscore collided: plain='$tail_plain' underscore='$tail_under'"
fi

# Test 16: an ephemeral credential is never written to the vault. git-credential(1)
# says a helper must not save the value in the credential field when ephemeral is
# set, and a stored copy would also be replayed on the next get.
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=eph.example\nusername=u\nauthtype=Digest\ncredential=nonce-bound\nephemeral=1\n\n' | "$HELPER" store 2>/dev/null
eph_out=$(printf 'protocol=https\nhost=eph.example\n\n' | "$HELPER" get 2>/dev/null)
if ! echo "$eph_out" | grep -q 'nonce-bound' && ! echo "$eph_out" | grep -q '^ephemeral=' \
    && ! echo "$eph_out" | grep -q '^authtype='; then
    pass "ephemeral credential is not stored"
else
    fail "ephemeral credential leaked into the vault, got: $eph_out"
fi

# Test 17: when git names the account it wants, a record for a different account
# is not an answer. git takes the helper's username over the one it asked for, so
# replying here would authenticate as the wrong person.
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=two.example\nusername=alice\npassword=alice-token\n\n' | "$HELPER" store 2>/dev/null
wrong_user=$(printf 'protocol=https\nhost=two.example\nusername=bob\n\n' | "$HELPER" get 2>/dev/null)
right_user=$(printf 'protocol=https\nhost=two.example\nusername=alice\n\n' | "$HELPER" get 2>/dev/null)
if [ -z "$wrong_user" ] && echo "$right_user" | grep -q '^password=alice-token$'; then
    pass "get stays silent when the stored account is not the one git asked for"
else
    fail "username mismatch mishandled: bob='$wrong_user' alice='$right_user'"
fi

# Test 18: credential.dotsecenv.useUsername gives each account its own key, so two
# accounts on one host stop overwriting each other. git reads the setting on the
# helper's behalf, so the case needs git installed.
if command -v git >/dev/null 2>&1; then
    ((TESTS_RUN++)) || true
    printf '[credential "dotsecenv"]\n\tuseUsername = true\n' > "$HOME/.gitconfig"
    printf 'protocol=https\nhost=multi.example\nusername=alice\npassword=alice-pw\n\n' | "$HELPER" store 2>/dev/null
    printf 'protocol=https\nhost=multi.example\nusername=bob\npassword=bob-pw\n\n' | "$HELPER" store 2>/dev/null
    scoped_alice=$(printf 'protocol=https\nhost=multi.example\nusername=alice\n\n' | "$HELPER" get 2>/dev/null)
    scoped_bob=$(printf 'protocol=https\nhost=multi.example\nusername=bob\n\n' | "$HELPER" get 2>/dev/null)
    rm -f "$HOME/.gitconfig"
    if echo "$scoped_alice" | grep -q '^password=alice-pw$' && echo "$scoped_bob" | grep -q '^password=bob-pw$'; then
        pass "useUsername keeps two accounts on one host apart"
    else
        fail "username scoping failed: alice='$scoped_alice' bob='$scoped_bob'"
    fi
else
    echo "  SKIP: git not installed, useUsername case not exercised"
fi

# Test 19: an IPv6 literal round-trips. git sends the brackets as part of the
# host (host=[::1]:8443), so they are encoded by name rather than falling through
# to the catch-all, and two ports on one address stay apart.
((TESTS_RUN++)) || true
printf 'protocol=https\nhost=[::1]:8443\nusername=u\npassword=p19a\n\n' | "$HELPER" store 2>/dev/null
printf 'protocol=https\nhost=[::1]:9443\nusername=u\npassword=p19b\n\n' | "$HELPER" store 2>/dev/null
v6a=$(printf 'protocol=https\nhost=[::1]:8443\n\n' | "$HELPER" get 2>/dev/null)
v6b=$(printf 'protocol=https\nhost=[::1]:9443\n\n' | "$HELPER" get 2>/dev/null)
v6key=$("$BIN" secret get 2>/dev/null | grep -c 'LBRK' || true)
if echo "$v6a" | grep -q '^password=p19a$' && echo "$v6b" | grep -q '^password=p19b$' \
    && [ "$v6key" -ge 1 ]; then
    pass "IPv6 host round-trips with brackets encoded by name"
else
    fail "IPv6 host failed: 8443='$v6a' 9443='$v6b' bracket_keys=$v6key"
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
