#!/usr/bin/env python3
"""Exercise satellite authentication with local Git repositories and API fixtures."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, stderr=subprocess.DEVNULL
    ).strip()


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mono = self.root / "monorepo"
        self.satellite = self.root / "satellite"
        for repo in (self.mono, self.satellite):
            repo.mkdir()
            git(repo, "init", "-b", "main")
            git(repo, "config", "user.name", "Test")
            git(repo, "config", "user.email", "test@example.invalid")
            git(repo, "config", "commit.gpgsign", "false")
        for name in ("plugin", "packages"):
            (self.mono / name).mkdir()
            (self.mono / name / "file").write_text("published\n")
        git(self.mono, "add", ".")
        git(self.mono, "commit", "-m", "Source")
        self.source_sha = git(self.mono, "rev-parse", "HEAD")
        git(self.mono, "update-ref", "refs/remotes/origin/main", self.source_sha)
        git(self.mono, "-c", "tag.gpgsign=false", "tag", "-a", "v1.2.3", "-m", "Release")
        self.tag_oid = git(self.mono, "rev-parse", "refs/tags/v1.2.3")
        (self.satellite / "file").write_text("published\n")
        git(self.satellite, "add", ".")
        self.message = (
            "Publish\n\n"
            f"Source-Commit: dotsecenv/dotsecenv@{self.source_sha}\n"
            f"Source-SHA: {self.source_sha}\n"
            "Source-Path: plugin\n"
            "Source-Tag: v1.2.3\n"
        )
        self.commit(self.message)
        self.author = "dotsecenv-automated-releases[bot]"
        self.valid = True
        self.github_signed = True
        self.tagger = "MihaiBojin"
        self.tag_valid = True

    def comparator(self):
        fake_bin = self.root / "bin"
        fake_bin.mkdir(exist_ok=True)
        objects = self.root / "objects.json"
        objects.write_text(json.dumps({
            self.satellite_sha: self.api_object("dotsecenv/plugin", self.satellite_sha),
            self.tag_oid: self.api_object("dotsecenv/dotsecenv", self.tag_oid),
        }))
        gh = fake_bin / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json,os,sys\n"
            "assert sys.argv[1] == 'api'\n"
            "oid = next((x[4:] for x in sys.argv if x.startswith('oid=')), sys.argv[2].split('/')[-1])\n"
            "with open(os.environ['API_OBJECTS']) as f: obj = json.load(f).get(oid)\n"
            "if sys.argv[2] == 'graphql': response = {'data': {'repository': {'object': obj}}}\n"
            "else: response = {'sha': oid, 'tagger': obj['tagger'], 'verification': obj['verification']}\n"
            "print(json.dumps(response))\n"
        )
        gh.chmod(0o755)
        env = dict(os.environ, SOURCE_DIR=str(self.mono / "plugin"), SATELLITE_DIR=str(self.satellite),
                   MONOREPO_DIR=str(self.mono), SATELLITE_REPO="dotsecenv/plugin", EXPECTED_SHA=self.source_sha,
                   API_OBJECTS=str(objects), GH_TOKEN="invalid-test-token")
        env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
        return subprocess.run(["bash", str(ROOT / "scripts/release/verify-satellite.sh")],
                              env=env, capture_output=True, text=True)

    def commit(self, message):
        git(self.satellite, "commit", "--allow-empty", "-m", message)
        self.satellite_sha = git(self.satellite, "rev-parse", "HEAD")

    def api_object(self, repo, oid):
        if repo == "dotsecenv/plugin":
            self.assertEqual(oid, self.satellite_sha)
            return {
                "__typename": "Commit", "oid": oid,
                "author": {"user": {"login": self.author}},
                "signature": {"isValid": self.valid, "wasSignedByGitHub": self.github_signed},
            }
        self.assertEqual(repo, "dotsecenv/dotsecenv")
        self.assertEqual(oid, self.tag_oid)
        return {
            "__typename": "Tag", "oid": oid,
            "tagger": {"email": "test@example.invalid", "user": {"login": self.tagger}},
            "verification": {"verified": self.tag_valid, "reason": "valid" if self.tag_valid else "unsigned"},
        }

    def verify(self, **kwargs):
        spec = importlib.util.spec_from_file_location(
            "provenance", ROOT / "scripts/release/verify-satellite-provenance.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module, "github_object", side_effect=self.api_object):
            return module.verify(self.satellite, self.mono, "dotsecenv/plugin", **kwargs)

    def test_valid_release(self):
        self.assertEqual(self.verify(expected_sha=self.source_sha, expected_tag="v1.2.3"), {
            "source_sha": self.source_sha, "source_tag": "v1.2.3",
            "satellite_sha": self.satellite_sha,
        })

    def test_unsigned_commit_is_rejected(self):
        self.valid = False
        with self.assertRaisesRegex(ValueError, "signature"):
            self.verify()

    def test_forged_author_with_other_signing_key_is_rejected(self):
        self.github_signed = False
        with self.assertRaisesRegex(ValueError, "GitHub"):
            self.verify()

    def test_other_author_is_rejected(self):
        self.author = "renovate[bot]"
        with self.assertRaisesRegex(ValueError, "author"):
            self.verify()

    def test_ambiguous_or_malformed_trailers_are_rejected(self):
        for suffix in (
            f"Source-SHA: {self.source_sha}\n",
            f"source-sha: {self.source_sha}\n",
            "Source-SHA: main\n",
        ):
            with self.subTest(suffix=suffix):
                self.commit(self.message + suffix)
                with self.assertRaisesRegex(ValueError, "Source-SHA"):
                    self.verify()

    def test_missing_or_ref_valued_sha_is_rejected(self):
        for value in ("", "main", "refs/pull/1/head", self.source_sha[:12]):
            with self.subTest(value=value):
                self.commit(self.message.replace(f"Source-SHA: {self.source_sha}\n", f"Source-SHA: {value}\n"))
                with self.assertRaisesRegex(ValueError, "Source-SHA"):
                    self.verify()

    def test_wrong_source_repository_or_path_is_rejected(self):
        for old, new in (("dotsecenv/dotsecenv@", "attacker/repo@"), ("Source-Path: plugin", "Source-Path: packages")):
            with self.subTest(new=new):
                self.commit(self.message.replace(old, new))
                with self.assertRaises(ValueError):
                    self.verify()

    def test_source_outside_main_is_rejected(self):
        git(self.mono, "commit", "--allow-empty", "-m", "Unmerged PR")
        other = git(self.mono, "rev-parse", "HEAD")
        self.commit(self.message.replace(self.source_sha, other).replace("Source-Tag: v1.2.3\n", ""))
        with self.assertRaisesRegex(ValueError, "main"):
            self.verify()

    def test_source_sha_must_identify_a_commit(self):
        self.commit(self.message.replace(self.source_sha, self.tag_oid).replace("Source-Tag: v1.2.3\n", ""))
        with self.assertRaisesRegex(ValueError, "commit"):
            self.verify()

    def test_main_can_advance_after_publication(self):
        git(self.mono, "commit", "--allow-empty", "-m", "Later main")
        git(self.mono, "update-ref", "refs/remotes/origin/main", "HEAD")
        self.assertEqual(self.verify()["source_sha"], self.source_sha)

    def test_tag_pointing_elsewhere_is_rejected(self):
        git(self.mono, "commit", "--allow-empty", "-m", "Later")
        git(self.mono, "-c", "tag.gpgsign=false", "tag", "-fa", "v1.2.3", "-m", "Moved")
        with self.assertRaisesRegex(ValueError, "Source-Tag"):
            self.verify()

    def test_untrusted_tag_signer_is_rejected(self):
        self.tagger = "attacker"
        with self.assertRaisesRegex(ValueError, "tag"):
            self.verify()

    def test_unsigned_tag_from_expected_tagger_is_rejected(self):
        self.tag_valid = False
        with self.assertRaisesRegex(ValueError, "tag"):
            self.verify()

    def test_lightweight_or_missing_tag_is_rejected(self):
        git(self.mono, "tag", "-d", "v1.2.3")
        with self.assertRaisesRegex(ValueError, "Source-Tag"):
            self.verify()
        git(self.mono, "-c", "tag.gpgsign=false", "tag", "v1.2.3")
        with self.assertRaisesRegex(ValueError, "annotated"):
            self.verify()

    def test_ad_hoc_publish_and_manual_rebuild(self):
        self.commit(self.message.replace("Source-Tag: v1.2.3\n", ""))
        self.assertEqual(self.verify(actor="MihaiBojin")["source_tag"], "")
        self.assertEqual(self.verify(actor=self.author, expected_sha=self.source_sha)["source_sha"], self.source_sha)

    def test_unauthorized_dispatch_or_missing_bot_input_is_rejected(self):
        for actor in ("attacker", self.author):
            with self.subTest(actor=actor), self.assertRaisesRegex(ValueError, "actor|source_sha"):
                self.verify(actor=actor)

    def test_dispatch_inputs_cannot_override_provenance(self):
        for kwargs in ({"expected_sha": "a" * 40}, {"expected_sha": "main"}, {"expected_tag": "v1.2.4"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.verify(**kwargs)

    def test_comparator_does_not_accept_unsigned_provenance(self):
        self.valid = False
        result = self.comparator()
        self.assertNotEqual(result.returncode, 0, "Unsigned satellite was accepted")
        self.assertIn("signature", result.stderr)

    def test_comparator_accepts_identical_authenticated_tree(self):
        result = self.comparator()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_comparator_rejects_changed_content_and_modes(self):
        (self.satellite / "file").write_text("tampered\n")
        self.assertNotEqual(self.comparator().returncode, 0)
        (self.satellite / "file").write_text("published\n")
        (self.satellite / "file").chmod(0o755)
        self.assertNotEqual(self.comparator().returncode, 0)

    def test_comparator_rejects_extra_symlink(self):
        (self.satellite / "extra").symlink_to("file")
        result = self.comparator()
        self.assertNotEqual(result.returncode, 0, "Untracked symlink was ignored")

    def test_comparator_rejects_newline_filename(self):
        (self.satellite / "file\nfile").write_text("hidden content\n")
        result = self.comparator()
        self.assertNotEqual(result.returncode, 0, "Newline filename hid an extra file")

    def test_comparator_checks_symlink_targets_and_file_types(self):
        old_sha = self.source_sha
        (self.mono / "plugin" / "link").symlink_to("file")
        git(self.mono, "add", ".")
        git(self.mono, "commit", "-m", "Published symlink")
        self.source_sha = git(self.mono, "rev-parse", "HEAD")
        git(self.mono, "update-ref", "refs/remotes/origin/main", self.source_sha)
        git(self.mono, "-c", "tag.gpgsign=false", "tag", "-fa", "v1.2.3", "-m", "Release")
        self.tag_oid = git(self.mono, "rev-parse", "refs/tags/v1.2.3")
        self.commit(self.message.replace(old_sha, self.source_sha))
        link = self.satellite / "link"
        link.symlink_to("file")
        result = self.comparator()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        link.unlink()
        link.symlink_to("./file")
        self.assertNotEqual(self.comparator().returncode, 0)
        link.unlink()
        link.symlink_to("file\n")
        self.assertNotEqual(self.comparator().returncode, 0, "Trailing newline in symlink target was ignored")
        link.unlink()
        link.write_text("published\n")
        self.assertNotEqual(self.comparator().returncode, 0)

    def test_comparator_rejects_wrong_source_checkout(self):
        git(self.mono, "commit", "--allow-empty", "-m", "Different checkout")
        git(self.mono, "update-ref", "refs/remotes/origin/main", "HEAD")
        result = self.comparator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Source checkout", result.stderr)

    def test_folded_sha_is_rejected(self):
        self.commit(self.message.replace(f"Source-SHA: {self.source_sha}", f"Source-SHA: {self.source_sha}\n continuation"))
        with self.assertRaisesRegex(ValueError, "Source-SHA"):
            self.verify()


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


class GitHubAPITests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "provenance", ROOT / "scripts/release/verify-satellite-provenance.py"
        )
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_tag_verification_uses_rest_and_authenticated_tagger(self):
        oid = "a" * 40
        tag = {"__typename": "Tag", "oid": oid,
               "tagger": {"email": "maintainer@example.invalid", "user": {"login": "MihaiBojin"}}}
        responses = [json.dumps({"data": {"repository": {"object": tag}}}), json.dumps({
            "sha": oid, "tagger": {"email": "maintainer@example.invalid"},
            "verification": {"verified": True, "reason": "valid"},
        })]
        with patch.object(self.module.subprocess, "check_output", side_effect=responses) as api:
            result = self.module.github_object("dotsecenv/dotsecenv", oid)
        self.assertTrue(result["verification"]["verified"])
        self.assertEqual(api.call_args_list[1].args[0], ["gh", "api", f"repos/dotsecenv/dotsecenv/git/tags/{oid}"])

    def test_api_error_or_wrong_oid_is_rejected(self):
        for response in ({"errors": [{"message": "denied"}]}, {"data": {"repository": {"object": None}}},
                         {"data": {"repository": {"object": {"oid": "b" * 40}}}}):
            with self.subTest(response=response), patch.object(self.module.subprocess, "check_output", return_value=json.dumps(response)):
                with self.assertRaises(ValueError):
                    self.module.github_object("dotsecenv/plugin", "a" * 40)

    def test_tag_api_must_match_the_requested_object(self):
        oid = "a" * 40
        tag = {"__typename": "Tag", "oid": oid, "tagger": {"email": "maintainer@example.invalid"}}
        for rest in ({"sha": "b" * 40, "tagger": {"email": "maintainer@example.invalid"}},
                     {"sha": oid, "tagger": {"email": "attacker@example.invalid"}}):
            with self.subTest(rest=rest), patch.object(self.module.subprocess, "check_output", side_effect=[
                json.dumps({"data": {"repository": {"object": tag}}}), json.dumps(rest),
            ]):
                with self.assertRaisesRegex(ValueError, "inconsistent"):
                    self.module.github_object("dotsecenv/dotsecenv", oid)


if __name__ == "__main__":
    unittest.main()
