#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType


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
        REPO_ROOT / "scripts" / "validate-agent-plugins.py",
        fixture / "scripts" / "validate-agent-plugins.py",
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
    for skill_name in ("secenv", "secrets", "vault"):
        skill_dir = fixture / "skills" / skill_name
        skill_dir.mkdir(parents=True)
        shutil.copy2(
            REPO_ROOT / "skills" / skill_name / "SKILL.md",
            skill_dir / "SKILL.md",
        )
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


def run_validator(fixture: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    require(UV is not None, "uv is required to run the plugin validator tests")
    return subprocess.run(
        [
            UV,
            "run",
            "--script",
            str(fixture / "scripts" / "validate-agent-plugins.py"),
            *arguments,
        ],
        cwd=fixture,
        check=False,
        capture_output=True,
        text=True,
    )


def load_version_module() -> ModuleType:
    module_path = REPO_ROOT / "scripts" / "set-plugin-version.py"
    spec = importlib.util.spec_from_file_location("set_plugin_version", module_path)
    require(spec is not None and spec.loader is not None, "cannot load version helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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


def test_duplicate_manifest_keys(test_root: Path) -> None:
    fixture = new_fixture(test_root, "duplicate-key")
    manifest_path = fixture / ".codex-plugin/plugin.json"
    contents = manifest_path.read_text(encoding="utf-8")
    contents = contents.replace(
        '"version": "0.8.0",',
        '"version": "0.8.0",\n  "version": "0.8.1",',
        1,
    )
    manifest_path.write_text(contents, encoding="utf-8")
    result = run_validator(fixture)
    require(result.returncode != 0, "validator accepted a duplicate manifest key")
    require(
        "duplicate JSON key: version" in result.stderr,
        f"validator did not identify the duplicate key: {result.stderr}",
    )


def test_replace_failure_has_clean_error(test_root: Path) -> None:
    module = load_version_module()
    target = test_root / "replace-failure" / "plugin.json"
    target.parent.mkdir()
    target.write_text("original", encoding="utf-8")
    pending = module.PendingUpdate(target, "original", "updated", 0o644)
    staged_path = module.stage_file(pending, pending.updated)
    staged = module.StagedUpdate(pending, staged_path)
    original_replace = module.os.replace

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("synthetic replace failure")

    module.os.replace = fail_replace
    try:
        try:
            module.apply_updates([staged])
        except SystemExit as error:
            message = str(error)
            require(
                message == "plugin version update failed: synthetic replace failure",
                f"unexpected replace failure message: {message}",
            )
            require(error.__cause__ is None, "replace failure retained an exception cause")
            require(error.__suppress_context__, "replace failure would print a traceback")
        else:
            raise AssertionError("replace failure did not exit")
    finally:
        module.os.replace = original_replace

    require(target.read_text(encoding="utf-8") == "original", "target was changed")
    require(not staged_path.exists(), "failed replace left a staged file")


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        test_root = Path(temporary_directory)
        test_plain_version_and_idempotence(test_root)
        test_prefixed_version(test_root)
        test_malformed_input(test_root)
        test_failed_transaction(test_root)
        test_duplicate_manifest_keys(test_root)
        test_replace_failure_has_clean_error(test_root)
    print("Agent plugin version helper tests passed")


if __name__ == "__main__":
    main()
