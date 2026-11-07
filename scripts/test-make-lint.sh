#!/usr/bin/env bash
# Exercise the Makefile's formatting check with real gofmt and disposable files.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

cp "$repo_root/Makefile" "$fixture/Makefile"
printf 'module example.com/lintfixture\n\ngo 1.20\n' > "$fixture/go.mod"
printf 'package lintfixture\n' > "$fixture/source.go"

# Isolate the formatting check from linter installation and configuration.
cat > "$fixture/linter" <<'LINTER'
#!/bin/sh
echo 'Linter invoked'
LINTER
chmod +x "$fixture/linter"

for directory in vendor/example.com/dependency nested/vendor/example.com/dependency nested/deeper/vendor/example.com/dependency; do
    mkdir -p "$fixture/$directory"
    printf 'package vendored\nfunc   unformatted( ){}\n' > "$fixture/$directory/third_party.go"
done

lint() {
    make --no-print-directory -C "$fixture" lint GOLANGCI_LINT="$fixture/linter"
}

if ! output=$(lint 2>&1); then
    printf 'FAIL: lint should ignore vendor directories at every depth\n%s\n' "$output" >&2
    exit 1
fi
if ! grep -qF 'Linter invoked' <<< "$output"; then
    echo 'FAIL: lint did not reach golangci-lint' >&2
    exit 1
fi

# First-party files must still fail the check, including names containing
# "vendor" that are not themselves vendor directory path segments.
for path in source.go nested/first_party.go myvendor/first_party.go; do
    mkdir -p "$fixture/$(dirname "$path")"
    printf 'package lintfixture\nfunc   unformatted( ){}\n' > "$fixture/$path"
    if output=$(lint 2>&1); then
        printf 'FAIL: lint accepted unformatted first-party file %s\n' "$path" >&2
        exit 1
    fi
    if ! grep -qxF "$path" <<< "$output"; then
        printf 'FAIL: lint did not report %s\n%s\n' "$path" "$output" >&2
        exit 1
    fi
    if grep -qF 'third_party.go' <<< "$output"; then
        printf 'FAIL: lint reported vendored files\n%s\n' "$output" >&2
        exit 1
    fi
    gofmt -w "$fixture/$path"
done

echo 'Makefile lint regression tests passed'
