#!/usr/bin/env python3
"""Exercise find-satellite-run.sh against a fake gh."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RunDiscoveryTests(unittest.TestCase):
    def test_dispatch_discovery_matches_published_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            gh = root / "gh"
            gh.write_text("#!/bin/sh\nprintf '%s\\n' " + "'" + json.dumps({
                "total_count": 2,
                "workflow_runs": [
                    {"id": 22, "head_sha": "b" * 40, "html_url": "https://example.invalid/22", "name": "Other"},
                    {"id": 11, "head_sha": "a" * 40, "html_url": "https://example.invalid/11", "name": "Expected"},
                ],
            }) + "'\n")
            gh.chmod(0o755)
            output = root / "output"
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       SATELLITE_REPO="dotsecenv/packages", SINCE="2026-11-07T00:00:00Z", GH_TOKEN="test",
                       HEAD_SHA="a" * 40, EVENT="workflow_dispatch", GITHUB_OUTPUT=str(output))
            result = subprocess.run(["bash", str(ROOT / "scripts/release/find-satellite-run.sh")],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("run_id=11\n", output.read_text())


if __name__ == "__main__":
    unittest.main()
