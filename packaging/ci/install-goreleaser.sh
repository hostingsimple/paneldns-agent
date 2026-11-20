#!/bin/sh
# Installs a pinned GoReleaser into $1 (default: $RUNNER_TEMP/bin), checking
# the tarball against a pinned SHA-256 before anything is unpacked. Used by
# the CI packages job and the release build job. To bump: take a released
# (not nightly) version, read the asset digest of goreleaser_Linux_x86_64.tar.gz
# from `gh api repos/goreleaser/goreleaser/releases/tags/<version>`, and
# update both values together.
set -eu

GORELEASER_VERSION=v2.20.2
GORELEASER_SHA256=f3d24969a7389a46613875711d15a96d8f6ef1553d84c6ace09d69ac1e7d44c0

dest="${1:-${RUNNER_TEMP:?}/bin}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

url="https://github.com/goreleaser/goreleaser/releases/download/${GORELEASER_VERSION}/goreleaser_Linux_x86_64.tar.gz"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/goreleaser.tar.gz" "$url"
echo "${GORELEASER_SHA256}  $tmp/goreleaser.tar.gz" | sha256sum -c -
mkdir -p "$dest"
tar -xzf "$tmp/goreleaser.tar.gz" -C "$tmp" goreleaser
install -m 0755 "$tmp/goreleaser" "$dest/goreleaser"
"$dest/goreleaser" --version | head -n 3
