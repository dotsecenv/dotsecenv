#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


SEMVER_RE = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


@dataclass(frozen=True)
class PendingUpdate:
    path: Path
    original: str
    updated: str
    mode: int


@dataclass(frozen=True)
class StagedUpdate:
    pending: PendingUpdate
    staged_path: Path


def plugin_version(value: str) -> str:
    if SEMVER_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            f"invalid plugin version {value!r}; expected [v]X.Y.Z"
        )
    return value.removeprefix("v")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synchronize the Claude Code and Codex plugin versions."
    )
    parser.add_argument("version", type=plugin_version, help="[v]X.Y.Z release version")
    return parser.parse_args()


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
        if offset >= len(contents) or contents[offset] == "}":
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


def prepare_update(path: Path, version: str) -> PendingUpdate | None:
    try:
        original = path.read_text(encoding="utf-8")
        payload = json.loads(original, object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"unable to read {path}: {error}") from error
    if not isinstance(payload, dict):
        raise SystemExit(f"manifest root must be an object: {path}")
    current_version = payload.get("version")
    if not isinstance(current_version, str):
        raise SystemExit(f"manifest has no string version: {path}")
    if current_version == version:
        return None

    return PendingUpdate(
        path=path,
        original=original,
        updated=replace_top_level_string(original, "version", version),
        mode=stat.S_IMODE(path.stat().st_mode),
    )


def stage_file(update: PendingUpdate, contents: str) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{update.path.name}.", suffix=".tmp", dir=update.path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, update.mode)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return temporary_path


def stage_updates(pending_updates: list[PendingUpdate]) -> list[StagedUpdate]:
    staged_updates: list[StagedUpdate] = []
    try:
        for pending in pending_updates:
            staged_updates.append(
                StagedUpdate(pending, stage_file(pending, pending.updated))
            )
    except BaseException:
        for staged in staged_updates:
            staged.staged_path.unlink(missing_ok=True)
        raise
    return staged_updates


def apply_updates(staged_updates: list[StagedUpdate]) -> None:
    replaced: list[PendingUpdate] = []
    try:
        for staged in staged_updates:
            os.replace(staged.staged_path, staged.pending.path)
            replaced.append(staged.pending)
    except BaseException as update_error:
        rollback_errors: list[str] = []
        for pending in reversed(replaced):
            try:
                rollback = stage_file(pending, pending.original)
                os.replace(rollback, pending.path)
            except BaseException as rollback_error:
                rollback_errors.append(f"{pending.path}: {rollback_error}")
        if rollback_errors:
            raise SystemExit(
                "plugin version update failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from update_error
        raise
    finally:
        for staged in staged_updates:
            staged.staged_path.unlink(missing_ok=True)


def main() -> None:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    manifest_paths = (
        repo_root / ".claude-plugin" / "plugin.json",
        repo_root / ".codex-plugin" / "plugin.json",
    )
    pending_updates = [
        update
        for path in manifest_paths
        if (update := prepare_update(path, args.version)) is not None
    ]
    if not pending_updates:
        print(f"Plugin manifests already use version {args.version}")
        return

    apply_updates(stage_updates(pending_updates))
    for update in pending_updates:
        print(f"Updated {update.path.relative_to(repo_root)} to {args.version}")


if __name__ == "__main__":
    main()
