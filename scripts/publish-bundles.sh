#!/usr/bin/env bash
# Publish the bundle set for the CURRENTLY committed generated/ to the durable
# store — a rolling `bundle-store` GitHub Release, one `bundles-<version>.tar.gz`
# per WhatsApp version. This is what makes a past generated/ reproducible after
# WhatsApp stops serving that version's bundles.
#
# CI's update workflow calls this automatically. Run it by hand only after a
# *manual* `whatspec update --save-bundles <dir>` bump, passing that same <dir>:
#
#   ./scripts/publish-bundles.sh <bundles-dir>
#
# Requires `gh` authenticated with `contents: write` on the repo.
set -euo pipefail
cd "$(dirname "$0")/.."

bundles_dir="${1:?usage: publish-bundles.sh <bundles-dir>  (the --save-bundles output)}"
[ -d "$bundles_dir" ] || { echo "not a directory: $bundles_dir" >&2; exit 1; }

ver=$(jq -r .waVersion generated/manifest.json)
[ -n "$ver" ] && [ "$ver" != "null" ] || { echo "no waVersion in generated/manifest.json" >&2; exit 1; }

# Content-addressed asset name: the input setHash (from the lock) makes a different
# bundle set a different asset, so an archive is never overwritten with different
# bytes — every past commit's lock keeps resolving the exact archive it pins. The
# version prefix keeps it browsable. Must match restore's `release_asset_url`.
sethash=$(jq -r .setHash generated/bundles.lock.json 2>/dev/null)
[ -n "$sethash" ] && [ "$sethash" != "null" ] || { echo "no setHash in generated/bundles.lock.json — run 'whatspec update' first" >&2; exit 1; }

# Build the archive in a temp dir (never in the working tree, so no stray file to
# `git add` by accident); `gh` names the asset from the basename regardless.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
archive="$work/bundles-${ver}-${sethash}.tar.gz"

# Prefer GNU tar for a reproducible archive (sorted, no owner/timestamps) — its
# `--sort`/`--mtime` flags are GNU extensions BSD tar (macOS) rejects. Fall back to
# gtar if installed, else a plain archive: byte-for-byte reproducibility of the
# envelope is a nicety here, since `restore` verifies each bundle's SHA-256 against
# the lock, not the tarball itself.
gnu_tar=""
if tar --version 2>/dev/null | grep -qi 'gnu tar'; then
  gnu_tar="tar"
elif command -v gtar >/dev/null 2>&1; then
  gnu_tar="gtar"
fi
if [ -n "$gnu_tar" ]; then
  "$gnu_tar" --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
      -C "$bundles_dir" -czf "$archive" .
else
  echo "note: GNU tar not found — writing a non-reproducible archive (restore still verifies per-bundle SHA-256)" >&2
  tar -C "$bundles_dir" -czf "$archive" .
fi

# One rolling release accumulates every set's asset; create it if absent.
gh release view bundle-store >/dev/null 2>&1 \
  || gh release create bundle-store --title "Bundle store" --latest=false \
       --notes "Durable WhatsApp Web bundle archives (content-addressed: bundles-<version>-<setHash>.tar.gz) for deterministic regeneration. See scripts/regen.sh."
# --clobber is safe here: the name carries the content hash, so re-uploading only
# ever replaces an asset with byte-identical content (idempotent).
gh release upload bundle-store "$archive" --clobber

echo "published $(basename "$archive") to the bundle-store release"
