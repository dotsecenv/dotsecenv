#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
EXPECTED_SEMVER_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"
)


def expected_version(value: str) -> str:
    if EXPECTED_SEMVER_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            f"invalid expected plugin version {value!r}; expected [v]X.Y.Z"
        )
    return value.removeprefix("v")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the shared Claude Code and Codex plugin packaging."
    )
    parser.add_argument(
        "expected_version",
        nargs="?",
        type=expected_version,
        help="optional [v]X.Y.Z version required in both manifests",
    )
    return parser.parse_args()


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


class PluginValidator:
    def __init__(self, repo_root: Path, expected: str | None) -> None:
        self.repo_root = repo_root.resolve()
        self.expected = expected
        self.errors: list[str] = []
        self.versions: dict[str, str] = {}
        self.catalog_version: Any = None

    def load_object(self, relative_path: str) -> dict[str, Any] | None:
        path = self.repo_root / relative_path
        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=reject_duplicate_keys,
            )
        except OSError as error:
            self.errors.append(f"cannot read {relative_path}: {error}")
            return None
        except (json.JSONDecodeError, ValueError) as error:
            self.errors.append(f"invalid JSON in {relative_path}: {error}")
            return None
        if not isinstance(value, dict):
            self.errors.append(f"{relative_path} must contain a JSON object")
            return None
        return value

    def validate_reference(self, raw_path: Any, label: str) -> None:
        if not isinstance(raw_path, str) or not raw_path:
            self.errors.append(f"{label} must be a non-empty relative path")
            return
        path = Path(raw_path)
        if path.is_absolute():
            self.errors.append(f"{label} must be relative to the plugin root")
            return
        candidate = (self.repo_root / path).resolve()
        if candidate != self.repo_root and self.repo_root not in candidate.parents:
            self.errors.append(f"{label} escapes the plugin root: {raw_path}")
            return
        if not candidate.is_file():
            self.errors.append(f"{label} references a missing file: {raw_path}")

    def validate_manifest(self, label: str, manifest: dict[str, Any] | None) -> None:
        if manifest is None:
            return
        if manifest.get("name") != "dotsecenv":
            self.errors.append(f"{label} manifest name must be dotsecenv")
        version = manifest.get("version")
        if not isinstance(version, str) or SEMVER_RE.fullmatch(version) is None:
            self.errors.append(f"{label} manifest version must be strict X.Y.Z semver")
            return
        self.versions[label] = version
        if self.expected is not None and version != self.expected:
            self.errors.append(
                f"{label} manifest version {version} does not match expected "
                f"version {self.expected}"
            )

    def validate_codex_manifest(self, manifest: dict[str, Any] | None) -> None:
        if manifest is None:
            return
        if manifest.get("skills") != "./skills/":
            self.errors.append("Codex manifest skills must point to ./skills/")

        for field in ("apps", "hooks"):
            if field in manifest:
                self.validate_reference(manifest[field], f"Codex manifest {field}")

        mcp_servers = manifest.get("mcpServers")
        if isinstance(mcp_servers, str):
            self.validate_reference(mcp_servers, "Codex manifest mcpServers")
        elif mcp_servers is not None and not isinstance(mcp_servers, dict):
            self.errors.append("Codex manifest mcpServers must be a path or object")

        interface = manifest.get("interface")
        if isinstance(interface, dict):
            self.validate_codex_interface(interface)
        elif interface is not None:
            self.errors.append("Codex manifest interface must be an object")

    def validate_codex_interface(self, interface: dict[str, Any]) -> None:
        for field in ("composerIcon", "logo", "logoDark"):
            if field in interface:
                self.validate_reference(interface[field], f"Codex interface {field}")
        screenshots = interface.get("screenshots", [])
        if not isinstance(screenshots, list):
            self.errors.append("Codex interface screenshots must be an array")
            return
        for index, screenshot in enumerate(screenshots):
            self.validate_reference(screenshot, f"Codex interface screenshots[{index}]")

    def validate_skills(self) -> None:
        skills_root = self.repo_root / "skills"
        expected_skills = {"secenv", "secrets", "vault"}
        if not skills_root.is_dir() or skills_root.is_symlink():
            self.errors.append(
                "skills/ must be the canonical, non-symlinked skills directory"
            )
            return

        actual_skills = {
            path.parent.name
            for path in skills_root.glob("*/SKILL.md")
            if path.is_file()
        }
        if actual_skills != expected_skills:
            self.errors.append(
                "skills/ must contain exactly secenv, secrets, and vault; found: "
                + ", ".join(sorted(actual_skills))
            )
        for skill_name in sorted(expected_skills):
            skill_path = skills_root / skill_name / "SKILL.md"
            if not skill_path.is_file():
                self.errors.append(
                    f"missing canonical skill: skills/{skill_name}/SKILL.md"
                )
            elif skill_path.is_symlink() or skill_path.parent.is_symlink():
                self.errors.append(f"canonical skill must not be symlinked: {skill_path}")

    def validate_no_product_skill_copies(self) -> None:
        for product_root in (
            self.repo_root / ".claude-plugin",
            self.repo_root / ".codex-plugin",
        ):
            for copied_skill in product_root.rglob("SKILL.md"):
                self.errors.append(
                    "product-specific skill copy is forbidden: "
                    + str(copied_skill.relative_to(self.repo_root))
                )
            product_skills = product_root / "skills"
            if product_skills.exists() or product_skills.is_symlink():
                self.errors.append(
                    "product-specific skills directory is forbidden: "
                    + str(product_skills.relative_to(self.repo_root))
                )

    def validate_marketplace(self, marketplace: dict[str, Any] | None) -> None:
        if marketplace is None:
            return
        metadata = marketplace.get("metadata")
        if isinstance(metadata, dict):
            self.catalog_version = metadata.get("version")
        if "version" in marketplace:
            self.catalog_version = marketplace["version"]

        plugins = marketplace.get("plugins")
        if not isinstance(plugins, list):
            self.errors.append("Claude marketplace plugins must be an array")
            return
        entries = [
            entry
            for entry in plugins
            if isinstance(entry, dict) and entry.get("name") == "dotsecenv"
        ]
        if len(entries) != 1:
            self.errors.append("Claude marketplace must contain one dotsecenv entry")
        for entry in entries:
            if "version" in entry:
                self.errors.append(
                    "Claude marketplace dotsecenv entry must not declare a plugin version"
                )

    def run(self) -> None:
        claude_manifest = self.load_object(".claude-plugin/plugin.json")
        codex_manifest = self.load_object(".codex-plugin/plugin.json")
        marketplace = self.load_object(".claude-plugin/marketplace.json")

        self.validate_manifest("Claude", claude_manifest)
        self.validate_manifest("Codex", codex_manifest)
        if (
            len(self.versions) == 2
            and self.versions["Claude"] != self.versions["Codex"]
        ):
            self.errors.append(
                "Claude and Codex manifest versions differ: "
                f"{self.versions['Claude']} != {self.versions['Codex']}"
            )
        self.validate_codex_manifest(codex_manifest)
        self.validate_skills()
        self.validate_no_product_skill_copies()
        self.validate_marketplace(marketplace)

    def report(self) -> None:
        if self.errors:
            print("Agent plugin validation failed:", file=sys.stderr)
            for error in self.errors:
                print(f"- {error}", file=sys.stderr)
            raise SystemExit(1)

        version = self.versions.get("Codex", "unknown")
        catalog_note = (
            f"; marketplace catalog version {self.catalog_version} remains independent"
            if self.catalog_version is not None
            else ""
        )
        print(
            f"Agent plugin validation passed (plugin version {version}{catalog_note})"
        )


def main() -> None:
    args = parse_args()
    validator = PluginValidator(Path(__file__).resolve().parent.parent, args.expected_version)
    validator.run()
    validator.report()


if __name__ == "__main__":
    main()
