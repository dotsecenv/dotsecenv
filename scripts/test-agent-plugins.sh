#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

new_fixture() {
  local name=$1
  local fixture=$test_root/$name
  mkdir -p "$fixture/scripts" "$fixture/.claude-plugin" "$fixture/.codex-plugin"
  cp "$repo_root/scripts/set-plugin-version.sh" "$fixture/scripts/"
  cp "$repo_root/.claude-plugin/plugin.json" "$fixture/.claude-plugin/"
  cp "$repo_root/.claude-plugin/marketplace.json" "$fixture/.claude-plugin/"
  cp "$repo_root/.codex-plugin/plugin.json" "$fixture/.codex-plugin/"
  printf '%s\n' "$fixture"
}

assert_versions() {
  local fixture=$1
  local expected=$2
  python3 - "$fixture" "$expected" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
expected = sys.argv[2]
for relative in (".claude-plugin/plugin.json", ".codex-plugin/plugin.json"):
    value = json.loads((root / relative).read_text(encoding="utf-8"))["version"]
    if value != expected:
        raise SystemExit(f"{relative}: expected {expected}, got {value}")
PY
}

assert_only_version_changed() {
  local before=$1
  local after=$2
  python3 - "$before" "$after" <<'PY'
import json
import sys
from pathlib import Path

before_text = Path(sys.argv[1]).read_text(encoding="utf-8")
after_text = Path(sys.argv[2]).read_text(encoding="utf-8")
before = json.loads(before_text)
after = json.loads(after_text)
old_version = before["version"]
new_version = after["version"]
old_member = f'"version": {json.dumps(old_version)}'
new_member = f'"version": {json.dumps(new_version)}'
expected_text = before_text.replace(old_member, new_member, 1)
if after_text != expected_text:
    raise SystemExit("manifest formatting or unrelated text changed")
before.pop("version")
after.pop("version")
if before != after:
    raise SystemExit("manifest fields other than version changed")
PY
}

inode() {
  if stat -c '%i' "$1" >/dev/null 2>&1; then
    stat -c '%i' "$1"
  else
    stat -f '%i' "$1"
  fi
}

plain_fixture=$(new_fixture plain)
cp "$plain_fixture/.claude-plugin/plugin.json" "$plain_fixture/claude.before.json"
cp "$plain_fixture/.codex-plugin/plugin.json" "$plain_fixture/codex.before.json"
cp "$plain_fixture/.claude-plugin/marketplace.json" "$plain_fixture/marketplace.before.json"
"$plain_fixture/scripts/set-plugin-version.sh" 0.8.1 >/dev/null
assert_versions "$plain_fixture" 0.8.1
assert_only_version_changed \
  "$plain_fixture/claude.before.json" "$plain_fixture/.claude-plugin/plugin.json"
assert_only_version_changed \
  "$plain_fixture/codex.before.json" "$plain_fixture/.codex-plugin/plugin.json"
cmp -s \
  "$plain_fixture/marketplace.before.json" \
  "$plain_fixture/.claude-plugin/marketplace.json" || \
  fail "marketplace catalog changed during version update"

claude_inode=$(inode "$plain_fixture/.claude-plugin/plugin.json")
codex_inode=$(inode "$plain_fixture/.codex-plugin/plugin.json")
"$plain_fixture/scripts/set-plugin-version.sh" 0.8.1 >/dev/null
[[ $(inode "$plain_fixture/.claude-plugin/plugin.json") == "$claude_inode" ]] || \
  fail "idempotent run rewrote the Claude manifest"
[[ $(inode "$plain_fixture/.codex-plugin/plugin.json") == "$codex_inode" ]] || \
  fail "idempotent run rewrote the Codex manifest"

prefixed_fixture=$(new_fixture prefixed)
"$prefixed_fixture/scripts/set-plugin-version.sh" v0.8.1 >/dev/null
assert_versions "$prefixed_fixture" 0.8.1

invalid_fixture=$(new_fixture invalid)
invalid_claude_sum=$(cksum "$invalid_fixture/.claude-plugin/plugin.json")
invalid_codex_sum=$(cksum "$invalid_fixture/.codex-plugin/plugin.json")
for malformed in "" 1.2 1.2.3.4 01.2.3 v1.2.3-rc.1; do
  if "$invalid_fixture/scripts/set-plugin-version.sh" "$malformed" >/dev/null 2>&1; then
    fail "accepted malformed version: $malformed"
  fi
done
if "$invalid_fixture/scripts/set-plugin-version.sh" >/dev/null 2>&1; then
  fail "accepted a missing version"
fi
if "$invalid_fixture/scripts/set-plugin-version.sh" 1.2.3 2.3.4 >/dev/null 2>&1; then
  fail "accepted more than one version"
fi
[[ $(cksum "$invalid_fixture/.claude-plugin/plugin.json") == "$invalid_claude_sum" ]] || \
  fail "malformed input changed the Claude manifest"
[[ $(cksum "$invalid_fixture/.codex-plugin/plugin.json") == "$invalid_codex_sum" ]] || \
  fail "malformed input changed the Codex manifest"

broken_fixture=$(new_fixture broken-manifest)
cp "$broken_fixture/.claude-plugin/plugin.json" "$broken_fixture/claude.before.json"
printf '%s\n' '{' >"$broken_fixture/.codex-plugin/plugin.json"
if "$broken_fixture/scripts/set-plugin-version.sh" 0.8.1 >/dev/null 2>&1; then
  fail "accepted a malformed Codex manifest"
fi
cmp -s \
  "$broken_fixture/claude.before.json" \
  "$broken_fixture/.claude-plugin/plugin.json" || \
  fail "partial update changed the Claude manifest"
[[ -z $(find "$broken_fixture" -name '*.tmp' -print -quit) ]] || \
  fail "failed transaction left a staged manifest behind"

echo "Agent plugin version helper tests passed"
