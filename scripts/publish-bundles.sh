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

archive="bundles-${ver}.tar.gz"
# Reproducible archive: sorted entries, no owner/timestamps.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
    -C "$bundles_dir" -czf "$archive" .

# One rolling release accumulates every version's asset; create it if absent.
gh release view bundle-store >/dev/null 2>&1 \
  || gh release create bundle-store --title "Bundle store" --latest=false \
       --notes "Durable WhatsApp Web bundle archives (one bundles-<version>.tar.gz per spec version) for deterministic regeneration. See scripts/regen.sh."
gh release upload bundle-store "$archive" --clobber

echo "published $archive to the bundle-store release"
