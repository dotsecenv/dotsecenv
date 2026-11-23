#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Set the release version that the Docs7 pages in docs/ write out.

The website renders these lines from the plugin manifest through Astro
components; docs/ holds the rendered text, so each release rewrites it.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SEMVER = r"\d+\.\d+\.\d+"

# (file, pattern with the version in group 2, how many lines must match)
TARGETS = (
    ("docs/tutorials/installation.mdx", rf"(dotsecenv_)({SEMVER})(_Darwin_)", 2),
    ("docs/tutorials/installation.mdx", rf"(?m)(^version: v)({SEMVER})($)", 1),
    ("docs/tutorials/installation.mdx", rf'(?m)(^VERSION=")({SEMVER})("$)', 1),
    ("docs/reference.mdx", rf"(?m)(^version: v)({SEMVER})($)", 1),
    ("docs/reference.mdx", rf'(?m)(^  "version": "v)({SEMVER})(",$)', 1),
)


def release_version(value: str) -> str:
    if re.fullmatch(rf"v?{SEMVER}", value) is None:
        raise argparse.ArgumentTypeError(f"invalid version {value!r}; expected [v]X.Y.Z")
    return value.removeprefix("v")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", type=release_version, help="[v]X.Y.Z release version")
    version = parser.parse_args().version
    repo_root = Path(__file__).resolve().parent.parent

    contents: dict[str, str] = {}
    for name, pattern, expected in TARGETS:
        text = contents.get(name) or (repo_root / name).read_text(encoding="utf-8")
        text, count = re.subn(pattern, rf"\g<1>{version}\g<3>", text)
        if count != expected:
            # A page changed shape; refuse rather than leave one copy stale.
            sys.exit(f"{name}: expected {expected} match(es) of {pattern!r}, found {count}")
        contents[name] = text

    # Write only after every pattern matched, so a refusal changes nothing.
    for name, text in contents.items():
        path = repo_root / name
        if path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
            print(f"Updated {name} to {version}")


if __name__ == "__main__":
    main()
