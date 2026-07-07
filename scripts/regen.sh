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

# --check compares against the committed generated/, so a wrong version makes the
# comparison meaningless — require a real waVersion (jq yields "null" for a missing
# field with exit 0, which would otherwise pass `--wa-version null` straight through).
ver=$(jq -r .waVersion generated/manifest.json 2>/dev/null || true)
[ -n "$ver" ] && [ "$ver" != "null" ] || { echo "generated/manifest.json missing or has no waVersion" >&2; exit 1; }

cargo run --release -p whatspec -- restore --from-lock "$lock" --out "$tmp/bundles"
cargo run --release -p whatspec -- update --bundles "$tmp/bundles" --wa-version "$ver" --check
