#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
UV = shutil.which("uv")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def seed_manifest(path: Path) -> None:
    contents = path.read_text(encoding="utf-8")
    current = json.loads(contents)["version"]
    old_member = f'"version": {json.dumps(current)}'
    seeded_member = '"version": "0.8.0"'
    path.write_text(contents.replace(old_member, seeded_member, 1), encoding="utf-8")


def new_fixture(test_root: Path, name: str) -> Path:
    fixture = test_root / name
    (fixture / "scripts").mkdir(parents=True)
    (fixture / ".claude-plugin").mkdir()
    (fixture / ".codex-plugin").mkdir()
    shutil.copy2(
        REPO_ROOT / "scripts" / "set-plugin-version.py",
        fixture / "scripts" / "set-plugin-version.py",
    )
    shutil.copy2(
        REPO_ROOT / ".claude-plugin" / "plugin.json",
        fixture / ".claude-plugin" / "plugin.json",
    )
    shutil.copy2(
        REPO_ROOT / ".claude-plugin" / "marketplace.json",
        fixture / ".claude-plugin" / "marketplace.json",
    )
    shutil.copy2(
        REPO_ROOT / ".codex-plugin" / "plugin.json",
        fixture / ".codex-plugin" / "plugin.json",
    )
    seed_manifest(fixture / ".claude-plugin" / "plugin.json")
    seed_manifest(fixture / ".codex-plugin" / "plugin.json")
    return fixture


def run_helper(fixture: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    require(UV is not None, "uv is required to run the version helper tests")
    return subprocess.run(
        [
            UV,
            "run",
            "--script",
            str(fixture / "scripts" / "set-plugin-version.py"),
            *arguments,
        ],
        cwd=fixture,
        check=False,
        capture_output=True,
        text=True,
    )


def assert_success(result: subprocess.CompletedProcess[str]) -> None:
    require(
        result.returncode == 0,
        f"helper failed with exit {result.returncode}: {result.stderr}",
    )


def assert_versions(fixture: Path, expected: str) -> None:
    for relative in (
        Path(".claude-plugin/plugin.json"),
        Path(".codex-plugin/plugin.json"),
    ):
        value = json.loads((fixture / relative).read_text(encoding="utf-8"))["version"]
        require(value == expected, f"{relative}: expected {expected}, got {value}")


def assert_only_version_changed(before_path: Path, after_path: Path) -> None:
    before_text = before_path.read_text(encoding="utf-8")
    after_text = after_path.read_text(encoding="utf-8")
    before = json.loads(before_text)
    after = json.loads(after_text)
    old_member = f'"version": {json.dumps(before["version"])}'
    new_member = f'"version": {json.dumps(after["version"])}'
    require(
        after_text == before_text.replace(old_member, new_member, 1),
        "manifest formatting or unrelated text changed",
    )
    before.pop("version")
    after.pop("version")
    require(before == after, "manifest fields other than version changed")


def test_plain_version_and_idempotence(test_root: Path) -> None:
    fixture = new_fixture(test_root, "plain")
    claude_before = fixture / "claude.before.json"
    codex_before = fixture / "codex.before.json"
    marketplace_before = fixture / "marketplace.before.json"
    shutil.copy2(fixture / ".claude-plugin/plugin.json", claude_before)
    shutil.copy2(fixture / ".codex-plugin/plugin.json", codex_before)
    shutil.copy2(fixture / ".claude-plugin/marketplace.json", marketplace_before)

    assert_success(run_helper(fixture, "0.8.1"))
    assert_versions(fixture, "0.8.1")
    assert_only_version_changed(claude_before, fixture / ".claude-plugin/plugin.json")
    assert_only_version_changed(codex_before, fixture / ".codex-plugin/plugin.json")
    require(
        marketplace_before.read_bytes()
        == (fixture / ".claude-plugin/marketplace.json").read_bytes(),
        "marketplace catalog changed during version update",
    )

    claude_inode = (fixture / ".claude-plugin/plugin.json").stat().st_ino
    codex_inode = (fixture / ".codex-plugin/plugin.json").stat().st_ino
    assert_success(run_helper(fixture, "0.8.1"))
    require(
        (fixture / ".claude-plugin/plugin.json").stat().st_ino == claude_inode,
        "idempotent run rewrote the Claude manifest",
    )
    require(
        (fixture / ".codex-plugin/plugin.json").stat().st_ino == codex_inode,
        "idempotent run rewrote the Codex manifest",
    )


def test_prefixed_version(test_root: Path) -> None:
    fixture = new_fixture(test_root, "prefixed")
    assert_success(run_helper(fixture, "v0.8.1"))
    assert_versions(fixture, "0.8.1")


def test_malformed_input(test_root: Path) -> None:
    fixture = new_fixture(test_root, "invalid")
    claude_before = (fixture / ".claude-plugin/plugin.json").read_bytes()
    codex_before = (fixture / ".codex-plugin/plugin.json").read_bytes()
    for arguments in (
        ("",),
        ("1.2",),
        ("1.2.3.4",),
        ("01.2.3",),
        ("v1.2.3-rc.1",),
        (),
        ("1.2.3", "2.3.4"),
    ):
        result = run_helper(fixture, *arguments)
        require(result.returncode != 0, f"accepted malformed arguments: {arguments}")
    require(
        (fixture / ".claude-plugin/plugin.json").read_bytes() == claude_before,
        "malformed input changed the Claude manifest",
    )
    require(
        (fixture / ".codex-plugin/plugin.json").read_bytes() == codex_before,
        "malformed input changed the Codex manifest",
    )


def test_failed_transaction(test_root: Path) -> None:
    fixture = new_fixture(test_root, "broken-manifest")
    claude_before = (fixture / ".claude-plugin/plugin.json").read_bytes()
    (fixture / ".codex-plugin/plugin.json").write_text("{\n", encoding="utf-8")
    result = run_helper(fixture, "0.8.1")
    require(result.returncode != 0, "accepted a malformed Codex manifest")
    require(
        (fixture / ".claude-plugin/plugin.json").read_bytes() == claude_before,
        "partial update changed the Claude manifest",
    )
    require(not list(fixture.rglob("*.tmp")), "failed transaction left a staged file")


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        test_root = Path(temporary_directory)
        test_plain_version_and_idempotence(test_root)
        test_prefixed_version(test_root)
        test_malformed_input(test_root)
        test_failed_transaction(test_root)
    print("Agent plugin version helper tests passed")


if __name__ == "__main__":
    main()
