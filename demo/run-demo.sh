#!/usr/bin/env bash
# End to end demo: build the demo image, start one deliberately vulnerable and
# one hardened container, then scan and prove both. Output goes to examples/.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=examples
mkdir -p "$OUT" /tmp/escapearmed-demo-share
EA="python3 -m escapearmed"

echo "[demo] building escapearmed-demo:latest"
docker build -q -t escapearmed-demo:latest demo >/dev/null
docker rm -f ea-vulnapp ea-hardened ea-sneaky >/dev/null 2>&1 || true

echo "[demo] starting containers"
# Same settings as demo/docker-compose.yml, as plain docker run so no compose plugin is needed.
docker run -d --name ea-vulnapp --privileged --pid=host --cap-add SYS_ADMIN \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /:/host:ro \
  -v /tmp/escapearmed-demo-share:/shared \
  escapearmed-demo:latest >/dev/null
docker run -d --name ea-hardened --user 10001:10001 --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --tmpfs /tmp \
  escapearmed-demo:latest >/dev/null
# Not privileged, no socket, no host mounts. Looks "medium" on paper.
docker run -d --name ea-sneaky --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  --cgroupns=host escapearmed-demo:latest >/dev/null
docker ps --filter name=ea- --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'

echo "[demo] static scans"
$EA scan compose demo/docker-compose.yml --no-color -o "$OUT/scan-compose.txt" || true
$EA scan compose demo/docker-compose.yml -f sarif -o "$OUT/scan-compose.sarif" || true
$EA scan dockerfile tests/fixtures/Dockerfile.nvidiascape tests/fixtures/Dockerfile.runcrace \
    --no-color -o "$OUT/scan-dockerfiles.txt" || true
$EA scan host --no-color -o "$OUT/scan-host.txt" || true
$EA scan image escapearmed-demo:latest --no-color -o "$OUT/scan-image.txt" || true

echo "[demo] active proof against the vulnerable container"
$EA prove ea-vulnapp --active --i-understand --yes --no-color \
    -o "$OUT/prove-vulnapp.txt" --emit-dir "$OUT/vulnapp" || true

echo "[demo] active proof against the hardened container"
$EA prove ea-hardened --active --i-understand --yes --no-color \
    -o "$OUT/prove-hardened.txt" --emit-dir "$OUT/hardened" || true

echo "[demo] active proof against the 'not privileged' container"
$EA prove ea-sneaky --active --i-understand --yes --no-color \
    -o "$OUT/prove-sneaky.txt" --emit-dir "$OUT/sneaky" || true

echo "[demo] checking for leftover canaries on the host"
if ls -A /tmp/escapearmed-demo-share | grep -q escapearmed-canary; then
  echo "LEFTOVER CANARY FOUND" | tee "$OUT/cleanup-check.txt"
else
  echo "no canary files left in /tmp/escapearmed-demo-share" | tee "$OUT/cleanup-check.txt"
fi
if grep -q escapearmed /proc/mounts; then
  echo "LEFTOVER MOUNT FOUND" | tee -a "$OUT/cleanup-check.txt"
else
  echo "no escapearmed mounts left on the host" | tee -a "$OUT/cleanup-check.txt"
fi

if [[ "${KEEP:-0}" != "1" ]]; then
  docker rm -f ea-vulnapp ea-hardened ea-sneaky >/dev/null 2>&1 || true
fi
echo "[demo] done, see $OUT/"
