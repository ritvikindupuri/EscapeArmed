#!/usr/bin/env bash
# Validate the generated Falco rules with the real Falco engine (falco -V) in Docker.
set -euo pipefail
cd "$(dirname "$0")/../.."
IMAGE=${FALCO_IMAGE:-falcosecurity/falco:0.45.2}
RULES=$(mktemp --suffix=.yaml)
python3 -m escapearmed gen-policy falco --all --falco-out "$RULES"
chmod 644 "$RULES"
docker run --rm -v "$RULES:/rules/escapearmed.yaml:ro" "$IMAGE" falco -V /rules/escapearmed.yaml
rm -f "$RULES"
