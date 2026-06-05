#!/usr/bin/env bash
# Fetch WhatsApp Web bundles and regenerate the versioned spec artifacts under
# `generated/`. Same entry point used locally and in CI.
#
#   ./scripts/update.sh                 # fetch from web.whatsapp.com
#   ./scripts/update.sh --bundles dir   # use pre-downloaded .js bundles (offline)
set -euo pipefail
cd "$(dirname "$0")/.."
exec cargo run --release -p whatspec -- update "$@"
