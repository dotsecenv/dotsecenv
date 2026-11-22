#!/usr/bin/env bash
# Tests for install.sh. Offline: a stub `git clone` copies this checkout.
#
# Usage: ./tests/test_install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REAL_GIT="$(command -v git)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PASSED=0
FAILED=0

# Stub git: `clone` copies the local plugin directory, everything else runs real git.
mkdir -p "$WORK_DIR/bin"
cat >"$WORK_DIR/bin/git" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == clone ]]; then
    dest="\${!#}"
    mkdir -p "\$dest" && cp -R "$PLUGIN_DIR/." "\$dest/"
    exit
fi
exec "$REAL_GIT" "\$@"
EOF
chmod +x "$WORK_DIR/bin/git"

fail() {
    echo "  FAIL: $*"
    FAILED=$((FAILED + 1))
}

# Fresh HOME for each test; sets T_HOME, DATA, NEW.
setup() {
    T_HOME="$(mktemp -d "$WORK_DIR/home.XXXXXX")"
    DATA="$T_HOME/.local/share/dotsecenv"
    NEW="$DATA/plugin"
    mkdir -p "$DATA" "$T_HOME/.config/fish"
    echo "secret vault data" >"$DATA/vault"
}

run_installer() {
    env -u XDG_DATA_HOME -u XDG_CONFIG_HOME -u ZDOTDIR \
        HOME="$T_HOME" PATH="$WORK_DIR/bin:$PATH" \
        "$BASH" "$PLUGIN_DIR/install.sh" "$@" >"$WORK_DIR/out.log" 2>&1 ||
        fail "install.sh $* exited non-zero: $(cat "$WORK_DIR/out.log")"
}

# Old layout as written by earlier versions of install.sh: copies plus rc lines.
make_legacy_copy_install() {
    local f
    for f in dotsecenv.plugin.bash dotsecenv.plugin.zsh _dotsecenv_core.sh; do
        cp "$PLUGIN_DIR/$f" "$DATA/$f"
    done
    cp "$PLUGIN_DIR/conf.d/dotsecenv.fish" "$DATA/dotsecenv.fish"
    printf '\n# dotsecenv shell plugin\nsource "%s"\n' "$DATA/dotsecenv.plugin.bash" >>"$T_HOME/.bashrc"
    printf '\n# dotsecenv shell plugin\nsource "%s"\n' "$DATA/dotsecenv.plugin.zsh" >>"$T_HOME/.zshrc"
    printf '\n# dotsecenv shell plugin\nsource "%s"\n' "$DATA/dotsecenv.fish" >>"$T_HOME/.config/fish/config.fish"
}

# Old layout as a git clone of the plugin repo straight into the data directory.
make_legacy_clone_install() {
    cp -R "$PLUGIN_DIR/." "$DATA/"
    local g=("$REAL_GIT" -C "$DATA" -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false -c core.hooksPath=/dev/null)
    "${g[@]}" init -q
    "${g[@]}" add -- . ':!vault'
    "${g[@]}" commit -qm init
    "${g[@]}" remote add origin https://github.com/dotsecenv/plugin.git
}

assert_vault() {
    [[ "$(cat "$DATA/vault" 2>/dev/null)" == "secret vault data" ]] || fail "vault is gone or changed"
}

assert_no_legacy_files() {
    local f
    for f in dotsecenv.plugin.bash dotsecenv.plugin.zsh dotsecenv.fish _dotsecenv_core.sh; do
        [[ ! -e "$DATA/$f" ]] || fail "$DATA/$f still present"
    done
}

run_test() {
    local name="$1" before=$FAILED
    echo "- $name"
    setup
    "$name"
    if [[ $FAILED -eq $before ]]; then
        PASSED=$((PASSED + 1))
    fi
}

test_uninstall_keeps_vault_next_to_legacy_copy_install() {
    make_legacy_copy_install
    run_installer --uninstall
    assert_vault
    assert_no_legacy_files
}

test_uninstall_keeps_vault_next_to_legacy_clone_install() {
    make_legacy_clone_install
    echo "mine" >"$DATA/notes.txt"
    run_installer --uninstall
    assert_vault
    assert_no_legacy_files
    [[ ! -e "$DATA/.git" ]] || fail ".git still present"
    [[ ! -e "$DATA/conf.d" ]] || fail "conf.d still present"
    [[ -f "$DATA/notes.txt" ]] || fail "untracked notes.txt removed"
}

test_uninstall_keeps_vault_next_to_new_install() {
    run_installer
    [[ -f "$NEW/dotsecenv.plugin.zsh" ]] || fail "plugin not installed to $NEW"
    assert_no_legacy_files
    run_installer --uninstall
    assert_vault
    [[ ! -e "$NEW" ]] || fail "$NEW still present"
}

test_uninstall_keeps_unknown_files_in_plugin_dir() {
    run_installer
    echo "keep" >"$NEW/vault"
    run_installer --uninstall
    [[ "$(cat "$NEW/vault" 2>/dev/null)" == "keep" ]] || fail "unknown file in $NEW removed"
    [[ ! -e "$NEW/dotsecenv.plugin.zsh" ]] || fail "plugin file still present"
}

test_install_migrates_legacy_install() {
    make_legacy_copy_install
    run_installer
    assert_vault
    assert_no_legacy_files
    [[ -f "$NEW/dotsecenv.plugin.bash" && -f "$NEW/dotsecenv.fish" ]] || fail "plugin not installed to $NEW"
    local rc
    for rc in "$T_HOME/.bashrc" "$T_HOME/.zshrc" "$T_HOME/.config/fish/config.fish"; do
        ! grep -q "source \"$DATA/[^p]" "$rc" || fail "$rc still sources the old path"
        [[ $(grep -c "source \"$NEW/" "$rc") -eq 1 ]] || fail "$rc should source $NEW once: $(cat "$rc")"
    done
}

test_install_migrates_legacy_clone_install() {
    make_legacy_clone_install
    run_installer --shell=zsh
    assert_vault
    assert_no_legacy_files
    [[ ! -e "$DATA/.git" ]] || fail ".git still present"
    [[ -f "$NEW/dotsecenv.plugin.zsh" ]] || fail "plugin not installed to $NEW"
}

echo "install.sh tests"
run_test test_uninstall_keeps_vault_next_to_legacy_copy_install
run_test test_uninstall_keeps_vault_next_to_legacy_clone_install
run_test test_uninstall_keeps_vault_next_to_new_install
run_test test_uninstall_keeps_unknown_files_in_plugin_dir
run_test test_install_migrates_legacy_install
run_test test_install_migrates_legacy_clone_install

echo "Passed: $PASSED, Failed: $FAILED"
[[ $FAILED -eq 0 ]]
