#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 [v]X.Y.Z" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

raw_version=$1
semver_re='^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if [[ ! $raw_version =~ $semver_re ]]; then
  echo "Invalid plugin version: $raw_version" >&2
  usage
  exit 2
fi
version=${raw_version#v}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)

python3 - "$repo_root" "$version" <<'PY'
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path


repo_root = Path(sys.argv[1])
version = sys.argv[2]
manifest_paths = (
    repo_root / ".claude-plugin" / "plugin.json",
    repo_root / ".codex-plugin" / "plugin.json",
)


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def skip_whitespace(contents: str, offset: int) -> int:
    while offset < len(contents) and contents[offset].isspace():
        offset += 1
    return offset


def replace_top_level_string(contents: str, key: str, value: str) -> str:
    decoder = json.JSONDecoder()
    offset = skip_whitespace(contents, 0)
    if offset >= len(contents) or contents[offset] != "{":
        raise ValueError("manifest root must be a JSON object")
    offset += 1

    while True:
        offset = skip_whitespace(contents, offset)
        if offset >= len(contents):
            break
        if contents[offset] == "}":
            break

        member_name, offset = decoder.raw_decode(contents, offset)
        if not isinstance(member_name, str):
            raise ValueError("manifest member name must be a string")
        offset = skip_whitespace(contents, offset)
        if offset >= len(contents) or contents[offset] != ":":
            raise ValueError(f"missing colon after manifest member {member_name!r}")
        value_start = skip_whitespace(contents, offset + 1)
        member_value, value_end = decoder.raw_decode(contents, value_start)

        if member_name == key:
            if not isinstance(member_value, str):
                raise ValueError(f"manifest member {key!r} must be a string")
            return contents[:value_start] + json.dumps(value) + contents[value_end:]

        offset = skip_whitespace(contents, value_end)
        if offset < len(contents) and contents[offset] == ",":
            offset += 1
            continue
        if offset < len(contents) and contents[offset] == "}":
            break
        raise ValueError(f"invalid JSON after manifest member {member_name!r}")

    raise ValueError(f"manifest is missing top-level member {key!r}")


def stage_file(path: Path, contents: str, mode: int) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return temporary_path


pending_updates: list[tuple[Path, str, str, int]] = []
for manifest_path in manifest_paths:
    try:
        original = manifest_path.read_text(encoding="utf-8")
        payload = json.loads(original, object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"Unable to read {manifest_path}: {error}") from error
    if not isinstance(payload, dict):
        raise SystemExit(f"Manifest root must be an object: {manifest_path}")
    current_version = payload.get("version")
    if not isinstance(current_version, str):
        raise SystemExit(f"Manifest has no string version: {manifest_path}")
    if current_version == version:
        continue

    updated = replace_top_level_string(original, "version", version)
    mode = stat.S_IMODE(manifest_path.stat().st_mode)
    pending_updates.append((manifest_path, original, updated, mode))

if not pending_updates:
    print(f"Plugin manifests already use version {version}")
    raise SystemExit(0)

updates: list[tuple[Path, str, str, int, Path]] = []
try:
    for manifest_path, original, updated, mode in pending_updates:
        staged = stage_file(manifest_path, updated, mode)
        updates.append((manifest_path, original, updated, mode, staged))
except BaseException:
    for _manifest_path, _original, _updated, _mode, staged in updates:
        staged.unlink(missing_ok=True)
    raise

replaced: list[tuple[Path, str, int]] = []
try:
    for manifest_path, original, _updated, mode, staged in updates:
        os.replace(staged, manifest_path)
        replaced.append((manifest_path, original, mode))
except BaseException as update_error:
    rollback_errors: list[str] = []
    for manifest_path, original, mode in reversed(replaced):
        try:
            rollback = stage_file(manifest_path, original, mode)
            os.replace(rollback, manifest_path)
        except BaseException as rollback_error:
            rollback_errors.append(f"{manifest_path}: {rollback_error}")
    if rollback_errors:
        raise SystemExit(
            "Plugin version update failed and rollback was incomplete: "
            + "; ".join(rollback_errors)
        ) from update_error
    raise
finally:
    for _manifest_path, _original, _updated, _mode, staged in updates:
        staged.unlink(missing_ok=True)

for manifest_path, _original, _updated, _mode, _staged in updates:
    print(f"Updated {manifest_path.relative_to(repo_root)} to {version}")
PY
