#!/usr/bin/env bash
# Publish the wasm payload set recorded in generated/wasm.lock.json to the durable
# store — the same rolling `bundle-store` GitHub Release, as its own
# `wasm-<wasmSetHash>.tar.xz` asset (content-addressed, no version: the payload set
# survives many WhatsApp rollouts, so an unchanged set is uploaded once instead of on
# every update run).
#
# Separate from the bundles archive on purpose: that asset's name is content-addressed
# on the JS input `setHash` the reproducibility gate depends on, so payloads must never
# be added to it (an already-published archive would change bytes under a fixed name).
#
# CI's update workflow calls this automatically after a `--wasm --wasm-out <dir>` run.
# By hand, pass that same <dir>:
#
#   ./scripts/publish-wasm.sh <wasm-dir>
#
# Requires `gh` authenticated with `contents: write` on the repo.
set -euo pipefail
cd "$(dirname "$0")/.."

wasm_dir="${1:?usage: publish-wasm.sh <wasm-dir>  (the --wasm-out output)}"
[ -d "$wasm_dir" ] || { echo "not a directory: $wasm_dir" >&2; exit 1; }

lock="generated/wasm.lock.json"
[ -f "$lock" ] || { echo "no $lock — run 'whatspec update --wasm' first" >&2; exit 1; }

sethash=$(jq -r .wasmSetHash "$lock")
[ -n "$sethash" ] && [ "$sethash" != "null" ] || { echo "no wasmSetHash in $lock" >&2; exit 1; }

# Only publish what the lock pins. A stray file in the directory would land in an asset
# whose name claims a different content hash, and restore would then reject it.
locked=$(jq -r '.wasm[].fileName' "$lock" | sort)
present=$(cd "$wasm_dir" && ls -1 ./*.wasm 2>/dev/null | sed 's|^\./||' | sort || true)
if [ "$locked" != "$present" ]; then
  echo "wasm directory does not match $lock:" >&2
  diff <(echo "$locked") <(echo "$present") >&2 || true
  exit 1
fi

command -v xz >/dev/null 2>&1 || { echo "xz not found — install xz-utils to publish the archive" >&2; exit 1; }
# See publish-bundles.sh: xz reads XZ_DEFAULTS/XZ_OPT before the command line, so clear
# them and pin the container/check for a deterministic, lzma-rs-decodable single-stream .xz.
unset XZ_OPT XZ_DEFAULTS

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
archive="$work/wasm-${sethash}.tar.xz"

gnu_tar=""
if tar --version 2>/dev/null | grep -qi 'gnu tar'; then
  gnu_tar="tar"
elif command -v gtar >/dev/null 2>&1; then
  gnu_tar="gtar"
fi
# The payloads are already compressed-ish binaries; -9 still roughly quarters them
# (~41 MB → ~7 MB measured). restore verifies each payload's SHA-256 against the lock,
# so envelope reproducibility is a nicety, not a correctness requirement.
if [ -n "$gnu_tar" ]; then
  "$gnu_tar" --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
      -C "$wasm_dir" -cf - . | xz -9 --format=xz --check=crc64 -T1 -c > "$archive"
else
  echo "note: GNU tar not found — writing a non-reproducible archive (restore still verifies per-payload SHA-256)" >&2
  tar -C "$wasm_dir" -cf - . | xz -9 --format=xz --check=crc64 -T1 -c > "$archive"
fi

gh release view bundle-store >/dev/null 2>&1 \
  || gh release create bundle-store --title "Bundle store" --latest=false \
       --notes "Durable WhatsApp Web bundle archives (content-addressed: bundles-<version>-<setHash>.tar.xz) for deterministic regeneration. See scripts/regen.sh."
# --clobber is safe: the name carries the content hash, so a re-upload only ever replaces
# an asset with byte-identical content (idempotent), and an unchanged payload set across
# WhatsApp versions resolves to the asset already published.
gh release upload bundle-store "$archive" --clobber

echo "published $(basename "$archive") to the bundle-store release"
