#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 [[v]X.Y.Z]" >&2
}

if [[ $# -gt 1 ]]; then
  usage
  exit 2
fi

expected_version=${1:-}
if [[ -n $expected_version ]]; then
  semver_re='^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
  if [[ ! $expected_version =~ $semver_re ]]; then
    echo "Invalid expected plugin version: $expected_version" >&2
    usage
    exit 2
  fi
  expected_version=${expected_version#v}
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)

python3 - "$repo_root" "$expected_version" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


repo_root = Path(sys.argv[1]).resolve()
expected_version = sys.argv[2]
semver_re = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
errors: list[str] = []


def load_object(relative_path: str) -> dict[str, Any] | None:
    path = repo_root / relative_path
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        errors.append(f"cannot read {relative_path}: {error}")
        return None
    except json.JSONDecodeError as error:
        errors.append(f"invalid JSON in {relative_path}: {error}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{relative_path} must contain a JSON object")
        return None
    return value


def validate_reference(raw_path: Any, label: str) -> None:
    if not isinstance(raw_path, str) or not raw_path:
        errors.append(f"{label} must be a non-empty relative path")
        return
    path = Path(raw_path)
    if path.is_absolute():
        errors.append(f"{label} must be relative to the plugin root")
        return
    candidate = (repo_root / path).resolve()
    if candidate != repo_root and repo_root not in candidate.parents:
        errors.append(f"{label} escapes the plugin root: {raw_path}")
        return
    if not candidate.is_file():
        errors.append(f"{label} references a missing file: {raw_path}")


claude_manifest = load_object(".claude-plugin/plugin.json")
codex_manifest = load_object(".codex-plugin/plugin.json")
marketplace = load_object(".claude-plugin/marketplace.json")

versions: dict[str, str] = {}
for label, manifest in (
    ("Claude", claude_manifest),
    ("Codex", codex_manifest),
):
    if manifest is None:
        continue
    if manifest.get("name") != "dotsecenv":
        errors.append(f"{label} manifest name must be dotsecenv")
    version = manifest.get("version")
    if not isinstance(version, str) or semver_re.fullmatch(version) is None:
        errors.append(f"{label} manifest version must be strict X.Y.Z semver")
    else:
        versions[label] = version

if len(versions) == 2 and versions["Claude"] != versions["Codex"]:
    errors.append(
        "Claude and Codex manifest versions differ: "
        f"{versions['Claude']} != {versions['Codex']}"
    )
if expected_version:
    for label, version in versions.items():
        if version != expected_version:
            errors.append(
                f"{label} manifest version {version} does not match expected "
                f"version {expected_version}"
            )

if codex_manifest is not None:
    if codex_manifest.get("skills") != "./skills/":
        errors.append("Codex manifest skills must point to ./skills/")

    for field in ("apps", "hooks"):
        if field in codex_manifest:
            validate_reference(codex_manifest[field], f"Codex manifest {field}")

    mcp_servers = codex_manifest.get("mcpServers")
    if isinstance(mcp_servers, str):
        validate_reference(mcp_servers, "Codex manifest mcpServers")
    elif mcp_servers is not None and not isinstance(mcp_servers, dict):
        errors.append("Codex manifest mcpServers must be a path or object")

    interface = codex_manifest.get("interface")
    if isinstance(interface, dict):
        for field in ("composerIcon", "logo", "logoDark"):
            if field in interface:
                validate_reference(interface[field], f"Codex interface {field}")
        screenshots = interface.get("screenshots", [])
        if not isinstance(screenshots, list):
            errors.append("Codex interface screenshots must be an array")
        else:
            for index, screenshot in enumerate(screenshots):
                validate_reference(
                    screenshot, f"Codex interface screenshots[{index}]"
                )
    elif interface is not None:
        errors.append("Codex manifest interface must be an object")

skills_root = repo_root / "skills"
expected_skills = {"secenv", "secrets", "vault"}
if not skills_root.is_dir() or skills_root.is_symlink():
    errors.append("skills/ must be the canonical, non-symlinked skills directory")
else:
    actual_skills = {
        path.parent.name
        for path in skills_root.glob("*/SKILL.md")
        if path.is_file()
    }
    if actual_skills != expected_skills:
        errors.append(
            "skills/ must contain exactly secenv, secrets, and vault; found: "
            + ", ".join(sorted(actual_skills))
        )
    for skill_name in sorted(expected_skills):
        skill_path = skills_root / skill_name / "SKILL.md"
        if not skill_path.is_file():
            errors.append(f"missing canonical skill: skills/{skill_name}/SKILL.md")
        elif skill_path.is_symlink() or skill_path.parent.is_symlink():
            errors.append(f"canonical skill must not be symlinked: {skill_path}")

for product_root in (repo_root / ".claude-plugin", repo_root / ".codex-plugin"):
    copied_skills = list(product_root.rglob("SKILL.md"))
    if copied_skills:
        for copied_skill in copied_skills:
            errors.append(
                "product-specific skill copy is forbidden: "
                + str(copied_skill.relative_to(repo_root))
            )
    product_skills = product_root / "skills"
    if product_skills.exists() or product_skills.is_symlink():
        errors.append(
            "product-specific skills directory is forbidden: "
            + str(product_skills.relative_to(repo_root))
        )

catalog_version: Any = None
if marketplace is not None:
    metadata = marketplace.get("metadata")
    if isinstance(metadata, dict):
        catalog_version = metadata.get("version")
    if "version" in marketplace:
        catalog_version = marketplace["version"]

    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list):
        errors.append("Claude marketplace plugins must be an array")
    else:
        dotsecenv_entries = [
            entry
            for entry in plugins
            if isinstance(entry, dict) and entry.get("name") == "dotsecenv"
        ]
        if len(dotsecenv_entries) != 1:
            errors.append("Claude marketplace must contain one dotsecenv entry")
        for entry in dotsecenv_entries:
            if "version" in entry:
                errors.append(
                    "Claude marketplace dotsecenv entry must not declare a plugin version"
                )

if errors:
    print("Agent plugin validation failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)

version = versions.get("Codex", "unknown")
catalog_note = (
    f"; marketplace catalog version {catalog_version} remains independent"
    if catalog_version is not None
    else ""
)
print(f"Agent plugin validation passed (plugin version {version}{catalog_note})")
PY
