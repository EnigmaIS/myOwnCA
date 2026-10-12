#!/usr/bin/env bash
# Usage: deploy-image.sh BUNDLE VERSION TRUST_FILE STATE_VOLUME
# The independently provisioned verifier must be on PATH.
set -euo pipefail
if [ "$#" -ne 4 ]; then
  echo "Usage: $0 BUNDLE VERSION TRUST_FILE STATE_VOLUME" >&2
  exit 2
fi
verified=$(myownca-verify --json image --bundle "$1" --version "$2" --trust "$3" --name ca)
reference=$(printf '%s' "$verified" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["image"])')
docker pull "$reference"
# Create a replacement without starting it. Validate state/backup and configure
# the proxy before starting it; no running container is removed by this command.
docker create --name "myownca-$2" --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges=true \
  --mount "type=volume,src=$4,dst=/var/lib/myownca" "$reference"
