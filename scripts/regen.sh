#!/usr/bin/env bash
# Deterministically reproduce and verify generated/ from the committed lockfile.
#
# Restores the *exact* bundle set generated/ was built from (from the durable
# release store, verified against generated/bundles.lock.json) and re-runs the
# generator in --check mode: exits non-zero if the committed generated/ is not
# byte-for-byte reproducible from those pinned inputs. No live WhatsApp fetch.
#
#   ./scripts/regen.sh
#
# This is the offline, deterministic counterpart to scripts/update.sh (which
# fetches the *current* live version from web.whatsapp.com).
set -euo pipefail
cd "$(dirname "$0")/.."

lock="generated/bundles.lock.json"
[ -f "$lock" ] || { echo "no $lock committed yet — run the update workflow once to bootstrap it" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ver=$(jq -r .waVersion generated/manifest.json)
cargo run --release -p whatspec -- restore --from-lock "$lock" --out "$tmp/bundles"
cargo run --release -p whatspec -- update --bundles "$tmp/bundles" --wa-version "$ver" --check
