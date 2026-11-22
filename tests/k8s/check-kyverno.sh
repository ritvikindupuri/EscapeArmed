#!/usr/bin/env bash
# Validate the generated Kyverno policy with the real kyverno CLI.
# Every file in violations/ must fail, good-pod.yaml must pass.
set -uo pipefail
cd "$(dirname "$0")/../.."
KYVERNO=${KYVERNO:-kyverno}
POLICY=$(mktemp --suffix=.yaml)
python3 -m escapearmed gen-policy kyverno --all --kyverno-out "$POLICY" || exit 1
cd tests/k8s
rc=0
for f in violations/*.yaml; do
  out=$($KYVERNO apply "$POLICY" --resource "$f" 2>&1)
  msg=$(printf '%s\n' "$out" | grep -o 'EscapeArmed EA0[0-9][0-9][^:]*' | head -n1)
  if printf '%s' "$out" | grep -q 'escapearmed-block-escape-primitives -> .* failed'; then
    printf 'BLOCKED  %-24s %s\n' "$(basename "$f" .yaml)" "$msg"
  else
    printf 'MISSED   %s\n' "$(basename "$f" .yaml)"; rc=1
  fi
done
if $KYVERNO apply "$POLICY" --resource good-pod.yaml 2>&1 | grep -q 'fail: 0'; then
  echo "ALLOWED  good-pod"
else
  echo "WRONGLY BLOCKED good-pod"; rc=1
fi
rm -f "$POLICY"
exit $rc
