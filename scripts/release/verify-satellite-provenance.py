#!/usr/bin/env python3
"""Authenticate a satellite commit and its monorepo source before using its trailers."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


SOURCE_REPO = "dotsecenv/dotsecenv"
RELEASE_APP = "dotsecenv-automated-releases[bot]"
RELEASE_TAGGER = "MihaiBojin"
SHA = re.compile(r"[0-9a-f]{40}")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")


def git(repo, *args, **kwargs):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, stderr=subprocess.PIPE, **kwargs
    ).strip()


def github_object(repo, oid):
    owner, name = repo.split("/")
    query = """
      query($owner: String!, $name: String!, $oid: GitObjectID!) {
        repository(owner: $owner, name: $name) {
          object(oid: $oid) {
            __typename oid
            ... on Commit {
              author { user { login } }
              signature { isValid wasSignedByGitHub }
            }
            ... on Tag {
              tagger { email user { login } }
            }
          }
        }
      }
    """
    response = json.loads(subprocess.check_output([
        "gh", "api", "graphql", "-f", f"query={query}",
        "-f", f"owner={owner}", "-f", f"name={name}", "-f", f"oid={oid}",
    ], text=True))
    if response.get("errors"):
        raise ValueError("GitHub could not authenticate the object")
    obj = ((response.get("data") or {}).get("repository") or {}).get("object")
    if not obj or obj.get("oid") != oid:
        raise ValueError("GitHub returned no matching signed object")
    if obj.get("__typename") == "Tag":
        tag = json.loads(subprocess.check_output([
            "gh", "api", f"repos/{repo}/git/tags/{oid}",
        ], text=True))
        if tag.get("sha") != oid or (tag.get("tagger") or {}).get("email") != (obj.get("tagger") or {}).get("email"):
            raise ValueError("GitHub returned inconsistent tag metadata")
        obj["verification"] = tag.get("verification") or {}
    return obj


def verify(satellite, monorepo, repo, expected_sha="", expected_tag="", actor=None):
    if repo not in ("dotsecenv/plugin", "dotsecenv/packages"):
        raise ValueError("Unsupported satellite repository")
    if actor is not None:
        if actor not in (RELEASE_APP, RELEASE_TAGGER):
            raise ValueError("Unauthorized dispatch actor")
        if actor == RELEASE_APP and not expected_sha:
            raise ValueError("Release App dispatch requires source_sha")
    if expected_sha and not SHA.fullmatch(expected_sha):
        raise ValueError("Expected source_sha must be a full lowercase commit SHA")
    if expected_tag and not TAG.fullmatch(expected_tag):
        raise ValueError("Expected source_tag must be a semver release tag")

    satellite_sha = git(satellite, "rev-parse", "HEAD")
    obj = github_object(repo, satellite_sha)
    signature = obj.get("signature") or {}
    if obj.get("__typename") != "Commit" or signature.get("isValid") is not True:
        raise ValueError("Satellite commit has no valid signature")
    if signature.get("wasSignedByGitHub") is not True:
        raise ValueError("Satellite commit must be signed by GitHub")
    author = (obj.get("author") or {}).get("user") or {}
    if author.get("login") != RELEASE_APP:
        raise ValueError("Satellite commit author is not the release App")

    message = git(satellite, "show", "-s", "--format=%B", satellite_sha)
    parsed = git(satellite, "interpret-trailers", "--parse", input=message)
    fields = {}
    canonical = {name.lower(): name for name in ("Source-SHA", "Source-Commit", "Source-Path", "Source-Tag")}
    for line in parsed.splitlines():
        key, _, value = line.partition(": ")
        if key.lower() not in canonical:
            continue
        name = canonical[key.lower()]
        if key != name or name in fields:
            raise ValueError(f"Ambiguous {name} trailer")
        fields[name] = value
    source_sha = fields.get("Source-SHA", "")
    if not SHA.fullmatch(source_sha):
        raise ValueError("Source-SHA must be one full lowercase commit SHA")
    if fields.get("Source-Commit") != f"{SOURCE_REPO}@{source_sha}":
        raise ValueError("Source-Commit does not match the monorepo and Source-SHA")
    if fields.get("Source-Path") != repo.split("/")[1]:
        raise ValueError("Source-Path does not match the satellite")
    if expected_sha and source_sha != expected_sha:
        raise ValueError("Source-SHA does not match the expected source_sha")
    try:
        if git(monorepo, "cat-file", "-t", source_sha) != "commit":
            raise ValueError("Source-SHA must identify a commit")
        git(monorepo, "merge-base", "--is-ancestor", source_sha, "refs/remotes/origin/main")
    except subprocess.CalledProcessError as exc:
        raise ValueError("Source-SHA is not reachable from monorepo main") from exc

    source_tag = fields.get("Source-Tag", "")
    if "Source-Tag" in fields and not TAG.fullmatch(source_tag):
        raise ValueError("Source-Tag must be a semver release tag")
    if expected_tag and source_tag != expected_tag:
        raise ValueError("Source-Tag does not match the expected source_tag")
    if source_tag:
        ref = f"refs/tags/{source_tag}"
        try:
            tag_oid = git(monorepo, "rev-parse", "--verify", ref)
            target = git(monorepo, "rev-parse", "--verify", f"{ref}^{{commit}}")
            kind = git(monorepo, "cat-file", "-t", tag_oid)
        except subprocess.CalledProcessError as exc:
            raise ValueError("Source-Tag does not exist in the monorepo") from exc
        if target != source_sha:
            raise ValueError("Source-Tag does not point to Source-SHA")
        if kind != "tag":
            raise ValueError("Release tag must be a signed annotated tag")
        tag = github_object(SOURCE_REPO, tag_oid)
        verification = tag.get("verification") or {}
        tagger = (tag.get("tagger") or {}).get("user") or {}
        if (tag.get("__typename") != "Tag" or verification.get("verified") is not True
                or verification.get("reason") != "valid" or tagger.get("login") != RELEASE_TAGGER):
            raise ValueError("Release tag must have a valid signature from the release maintainer")
    if git(satellite, "rev-parse", "HEAD") != satellite_sha:
        raise ValueError("Satellite HEAD changed during verification")
    return {"source_sha": source_sha, "source_tag": source_tag, "satellite_sha": satellite_sha}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actor")
    args = parser.parse_args()
    try:
        result = verify(
            Path(os.environ["SATELLITE_DIR"]), Path(os.environ["MONOREPO_DIR"]),
            os.environ["SATELLITE_REPO"], os.environ.get("EXPECTED_SHA", ""),
            os.environ.get("EXPECTED_TAG", ""), args.actor,
        )
        if output := os.environ.get("GITHUB_OUTPUT"):
            with open(output, "a", encoding="utf-8") as stream:
                for name, value in result.items():
                    stream.write(f"{name}={value}\n")
        print(json.dumps(result))
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        print(f"Satellite provenance rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
