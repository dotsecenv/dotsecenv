#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Test scripts/set-docs-version.py against copies of the real docs pages."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PAGES = ("docs/tutorials/installation.mdx", "docs/reference.mdx")


def fixture(root: Path) -> Path:
    (root / "scripts").mkdir()
    shutil.copy2(REPO_ROOT / "scripts" / "set-docs-version.py", root / "scripts")
    for page in PAGES:
        (root / page).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / page, root / page)
    return root


def run(root: Path, version: str) -> subprocess.CompletedProcess[str]:
    script = root / "scripts" / "set-docs-version.py"
    return subprocess.run([sys.executable, str(script), version], capture_output=True, text=True)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = fixture(Path(tmp))

        result = run(root, "v9.8.7")
        assert result.returncode == 0, result.stderr
        install = (root / PAGES[0]).read_text(encoding="utf-8")
        reference = (root / PAGES[1]).read_text(encoding="utf-8")
        assert install.count("dotsecenv_9.8.7_Darwin_") == 2
        assert "\nversion: v9.8.7\n" in install and '\nVERSION="9.8.7"\n' in install
        assert "\nversion: v9.8.7\n" in reference and '\n  "version": "v9.8.7",\n' in reference

        result = run(root, "9.8.7")
        assert result.returncode == 0 and result.stdout == "", result.stdout

        # A page whose line moved is refused, and neither page is written.
        (root / PAGES[1]).write_text(reference.replace("version: v9.8.7", "ver: v9.8.7"), encoding="utf-8")
        result = run(root, "1.2.3")
        assert result.returncode != 0 and "docs/reference.mdx" in result.stderr, result.stderr
        assert (root / PAGES[0]).read_text(encoding="utf-8") == install

        assert run(root, "1.2").returncode != 0
    print("set-docs-version tests passed")


if __name__ == "__main__":
    main()
