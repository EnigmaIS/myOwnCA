#!/usr/bin/env bash
# Invoke only after authenticating this bundle and the external verifier.
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "Usage: bash deploy-compose.sh /absolute/path/to/release-trust.json" >&2
  exit 2
fi
bundle=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
myownca-verify --json artifact --bundle "$bundle" --version '0.17.2' --trust "$1"
# Read only the explicitly selected, signed Compose file (no automatic overrides).
# Ignore caller COMPOSE_FILE/COMPOSE_PROFILES; the template contains no interpolation.
docker compose --project-name myownca --project-directory "$bundle" \
  --env-file /dev/null -f "$bundle/compose.yaml" pull
docker compose --project-name myownca --project-directory "$bundle" \
  --env-file /dev/null -f "$bundle/compose.yaml" create
echo "Verified release 0.17.2 prepared, but not started."
echo "Complete backup and maintenance checks, then use the documented start command."
