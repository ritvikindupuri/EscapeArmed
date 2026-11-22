<p align="center">
  <img src="docs/assets/logo.png" alt="EscapeArmed logo" width="140">
</p>

<h1 align="center">EscapeArmed</h1>

<p align="center"><b>Prove whether a container can escape, then generate the policy that stops it.</b></p>

<p align="center">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue">
  <img alt="Platform: Linux" src="https://img.shields.io/badge/platform-Linux-informational">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-supported-2496ED?logo=docker&logoColor=white">
  <img alt="Kyverno" src="https://img.shields.io/badge/Kyverno-ValidatingPolicy-3784c5">
  <img alt="Falco" src="https://img.shields.io/badge/Falco-rules-00b4c8">
  <img alt="SARIF" src="https://img.shields.io/badge/SARIF-2.1.0-181717?logo=github">
</p>

## Overview

EscapeArmed answers one question about a container: **can it reach the host?**

It does this in three steps:

- **Find.** It reads how a workload runs (a live container, an image, a Dockerfile, a compose file, or the host) and flags escape primitives: privileged mode, dangerous capabilities, mounted runtime sockets, host path mounts, shared host namespaces, disabled AppArmor or seccomp, host cgroup namespaces, root without user namespaces, and the setups behind the November 2025 runc escapes and NVIDIAScape.
- **Prove.** If you opt in, it runs harmless canary probes inside a container you own and reports which escape steps actually work on this host, instead of guessing from version numbers.
- **Fix.** It turns the findings into a Kyverno policy that blocks them at admission, Falco rules that alert on them at runtime, and SARIF for GitHub code scanning and CI.

**Why proof matters.** A config-only scanner sees "SYS_ADMIN" and says medium. In the demo, EscapeArmed proved that a container with no privileged flag, no socket and no host mounts could still escape through the cgroup release_agent path. It also proved that a hardened container blocked every probe. That is the evidence a finding needs before someone acts on it.

## Key Features

- **25 detection rules** across five targets: running containers, images (including their layers), Dockerfiles, compose files, and the host. Each rule has a severity, a fix, and its CVE mapping. `escapearmed rules` lists them.
- **2025 escape CVEs.** runc CVE-2025-31133, CVE-2025-52565 and CVE-2025-52881, and NVIDIA Container Toolkit CVE-2025-23266 (NVIDIAScape). Image layer checks flag `/dev` symlinks, procfs symlinks and device nodes, the setup step for the runc mount races.
- **12 canary probes** that prove whether an escape actually works on this host. Two required flags plus a typed confirmation, no writes to kernel settings, a read-only API call, automatic cleanup, and a cleanup line in every report.
- **Clear verdict.** Each container gets `ESCAPABLE`, `AT RISK` or `NO ESCAPE PATH PROVEN`, and each finding is tagged `[PROVEN]`, `[LIKELY]` or `[BLOCKED]`.
- **Admission and runtime policy.** A Kyverno `ValidatingPolicy` (CEL, Kyverno 1.17+) covering only what was found, or every rule with `--all`. Self-contained Falco rules tailored to the mount paths that were found. Verified with the Kyverno CLI v1.20.0 and `falco -V` on Falco 0.45.2.
- **CI ready.** SARIF 2.1.0 with file and line locations, `--fail-on` severity gates, and `--fail-on-escape` for proven escapes.
- **Light footprint.** One dependency (PyYAML). Works with any Docker context. Probes run in busybox, dash or bash images.

## System Architecture

The diagram shows how a target moves through EscapeArmed, from input to enforcement.

<p align="center">
  <img src="docs/assets/architecture.png" alt="EscapeArmed system architecture" width="100%">
</p>
<p align="center"><b>Figure 1. EscapeArmed system architecture: inputs flow through analysis, optional live proof and generation into enforcement and reports</b></p>

1. **Inputs.** A live container, an image, a Dockerfile, a compose file, or the host.
2. **Analyze.** Those inputs become one workload model. The scanner then applies 25 rules and the CVE catalog.
3. **Prove (optional).** With `--active --i-understand`, harmless canary probes run inside a container you own. Results are attached to the matching findings.
4. **Generate.** The text and JSON report, SARIF, a Kyverno policy, and Falco rules are written from the findings and any proof.
5. **Enforce.** Upload SARIF to GitHub, apply the Kyverno policy, load the Falco rules, and gate CI on the exit code.

## Tech Stack

- **Container engine:** Docker Engine and CLI (tested with 28.5.2), runc (tested with 1.3.6), BuildKit and buildx.
- **Host:** Linux with cgroup v2, AppArmor and seccomp. Developed and tested on Kali Linux Rolling 2026.3, kernel 7.1.5.
- **Probe runtime:** POSIX sh (busybox, dash or bash) inside the container, using curl, perl, python3 or socat for the socket check if one is present.
- **Policy engine:** Kyverno 1.17 or later (`policies.kyverno.io/v1` `ValidatingPolicy` with CEL) on Kubernetes.
- **Runtime security:** Falco rules format 0.31 or later, validated on Falco 0.45.2.
- **CI and reporting:** SARIF 2.1.0, GitHub code scanning, GitHub Actions.
- **Packaging:** Python 3.9 or later, PyYAML, setuptools, and pytest for tests.
- **Diagram and logo:** SVG rendered with cairosvg, icons from Simple Icons (CC0) and CNCF artwork.

## Setup Instructions

Steps 1 to 3 install EscapeArmed. Steps 4 to 6 are optional checks.

**1. Install prerequisites (Kali, Debian or Ubuntu)**

```bash
sudo apt update
sudo apt install -y git python3 python3-venv docker.io
sudo systemctl enable --now docker
```

**2. Let your user run Docker without sudo**

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker info --format '{{.ServerVersion}}'
```

- `newgrp docker` applies the group in the current shell. Logging out and back in does the same for every shell.
- Prefer sudo instead? Skip this step and run `export ESCAPEARMED_DOCKER="sudo docker"` before using EscapeArmed.

**3. Clone and install**

```bash
git clone https://github.com/ritvikindupuri/EscapeArmed.git
cd EscapeArmed
python3 -m venv .venv
. .venv/bin/activate
pip install .
escapearmed --version
```

- The virtual environment is required on Kali and recent Debian, which block system-wide `pip install`.
- In a new shell, run `. .venv/bin/activate` from the repo folder before using `escapearmed`.

**4. Run the unit tests (optional)**

```bash
pip install ".[test]"
pytest -q
```

**5. Run the demo (optional)**

```bash
./demo/run-demo.sh
ls examples/
```

- Builds a demo image, starts three containers, scans and proves them, and cleans up. Details are in [Usage step 10](#10-run-the-demo).

**6. Check generated policy against the real engines (optional)**

```bash
# Kyverno CLI
curl -sSL -o /tmp/kyverno.tgz https://github.com/kyverno/kyverno/releases/download/v1.20.0/kyverno-cli_v1.20.0_linux_x86_64.tar.gz
tar -xzf /tmp/kyverno.tgz -C /tmp kyverno
KYVERNO=/tmp/kyverno tests/k8s/check-kyverno.sh

# Falco (runs in Docker)
tests/falco/check-falco.sh
```

## Usage Guide

### Usage at a glance

| Task | Command |
|---|---|
| Scan running containers | `escapearmed scan container web-1` |
| Scan every running container | `escapearmed scan all-containers` |
| Scan an image | `escapearmed scan image myorg/app:1.4` |
| Scan a Dockerfile | `escapearmed scan dockerfile Dockerfile` |
| Scan a compose file | `escapearmed scan compose docker-compose.yml` |
| Scan the host | `escapearmed scan host` |
| Prove escape paths (active) | `escapearmed prove my-test-container --active --i-understand` |
| Save JSON or SARIF | `escapearmed scan compose docker-compose.yml -f sarif -o escapearmed.sarif` |
| Generate Kyverno and Falco | `escapearmed gen-policy both --from report.json --kyverno-out policy.yaml --falco-out falco.yaml` |
| List rules and CVEs | `escapearmed rules` |
| Run the demo | `./demo/run-demo.sh` |

### Common options

These work on both `scan` and `prove`:

- `-f text` (default), `-f json` or `-f sarif` sets the output format.
- `-o FILE` writes the output to a file instead of the terminal.
- `--emit-dir DIR` also writes `report.txt`, `report.json`, `escapearmed.sarif`, `kyverno-policy.yaml` and `falco-rules.yaml` into `DIR`.
- `--fail-on SEVERITY` exits with code 2 if any finding is at or above `critical`, `high`, `medium`, `low` or `info`.
- `--no-color` turns off colors. Colors are also off when writing to a file.

Global options go before the command:

- `--docker CMD` sets the docker command, for example `escapearmed --docker "sudo docker" scan host`. The `ESCAPEARMED_DOCKER` variable does the same.
- `--version` prints the version. `-h` after any command lists its flags.

### 1. Scan a running container

```bash
escapearmed scan container web-1
escapearmed scan container web-1 api-1 worker-1
escapearmed scan all-containers
```

- Reads `docker inspect` for each container.
- Also runs the host checks (runc version, NVIDIA toolkit, user namespaces, socket permissions), since they affect every container on the host.

### 2. Scan an image

```bash
escapearmed scan image myorg/app:1.4
escapearmed scan image myorg/app:1.4 --no-layers
```

- Checks the image config (user, environment, GPU labels) and walks every layer for `/dev` symlinks, procfs symlinks and device nodes.
- `--no-layers` skips the layer walk, which helps with very large images.

### 3. Scan a Dockerfile

```bash
escapearmed scan dockerfile Dockerfile
escapearmed scan dockerfile build/*.Dockerfile --with-host
```

- Flags `ENV LD_PRELOAD`, steps that replace `/dev/null` or `/dev/console` or link into `/proc`, `RUN --security=insecure`, GPU base images and a missing `USER`.
- `--with-host` adds the host checks to a file scan.
- The fixtures under `tests/fixtures/` show how NVIDIAScape (`EA017`) and runc race setup (`EA020`, `EA021`) appear in a Dockerfile scan.

### 4. Scan a compose file

```bash
escapearmed scan compose docker-compose.yml
```

- Checks every service and points each finding to its exact line.

Sample from the demo compose file:

```text
CRITICAL EA001 Privileged container  (demo/docker-compose.yml:6)
CRITICAL EA002 Dangerous Linux capability added  (demo/docker-compose.yml:29)
CRITICAL EA003 Container runtime socket mounted  (demo/docker-compose.yml:11)
```

### 5. Scan the host

```bash
escapearmed scan host
```

- Compares runc and NVIDIA toolkit versions with the fixed releases, and checks daemon user namespace settings and Docker socket permissions.

### 6. Prove escape paths (active mode)

`prove` goes beyond reading config: it runs probes inside a live container. Only use it on containers you own or are authorized to test (see the [safety note](#safety-note-on-active-mode) below).

```bash
escapearmed prove my-test-container --active --i-understand
```

- `--active` and `--i-understand` are both required. Without them the command exits with code 64 and does nothing.
- You then type the container name to confirm. In scripts, pass `--yes` instead. Without a terminal and without `--yes`, it refuses to run.
- `--as-root` runs the probes as UID 0, modelling an attacker who already has root inside. By default they run as the container's own user.
- `--remote-daemon` skips the host side canary check when Docker runs on another machine. Canary writes are then reported as LIKELY.
- `--fail-on-escape` exits with code 3 when the verdict is ESCAPABLE.

For automation, with every artifact saved to one folder:

```bash
escapearmed prove my-test-container --active --i-understand --yes --emit-dir out/ --fail-on-escape
```

**Demo contrast** on the Kali demo host:

- `ea-sneaky` is not privileged, has no socket and no host mounts, and only adds `SYS_ADMIN`. Verdict: `ESCAPABLE`. Proved the cgroup release_agent path and `mount(2)`.
- `ea-vulnapp` is privileged, with host PID, a Docker socket, host root and a writable host directory. Verdict: `ESCAPABLE`. Proved runtime API access, a host bind-mount write (canary verified on the host), writable `core_pattern`, and a raw disk read.
- `ea-hardened` is non-root, with no capabilities, a read-only root and no-new-privileges. Verdict: `NO ESCAPE PATH PROVEN`. Every probe came back BLOCKED or NA.

```text
ea-sneaky    Verdict: ESCAPABLE
  PROVEN   cgroup v1 release_agent escape reachable
  PROVEN   mount(2) reachable
  Cleanup: 0 canary file(s) removed, nothing left behind

ea-vulnapp   Verdict: ESCAPABLE
  PROVEN   Runtime API reachable from container
  PROVEN   Write to host filesystem through a bind mount
  Cleanup: 1 canary file(s) removed, nothing left behind

ea-hardened  Verdict: NO ESCAPE PATH PROVEN
```

Full outputs and screenshots are in [`examples/`](examples/) and the [demo security assessment report](https://github.com/ritvikindupuri/EscapeArmed/blob/main/docs/DEMO-REPORT.md).

#### Safety note on active mode

- Only run `prove` against containers you own or are authorized to test.
- Nothing is ever written to `core_pattern`, `sysrq-trigger`, `release_agent`, `binfmt_misc` or kernel modules. Those checks test write access only and say "Not written".
- The runtime socket check sends one read-only `GET /version`. It never creates containers.
- The only write is one canary file per writable host bind mount, holding a random token. It is checked from the host and then removed, and the report says whether anything was left.
- Scratch mounts (a 1 MB tmpfs and an empty named cgroup v1 hierarchy) are unmounted by a trap, even on errors.
- Raw disk access is tested by reading 512 bytes into `/dev/null`.

### 7. Save JSON and SARIF

```bash
escapearmed scan container web-1 -f json -o report.json
escapearmed scan compose docker-compose.yml -f sarif -o escapearmed.sarif
```

- **JSON** holds the targets, host facts, a severity summary and every finding with evidence. After `prove`, it also holds the probe results and verdict. `gen-policy` reads this file.
- **SARIF** has one rule entry per EscapeArmed rule, `security-severity` scores for GitHub, and file and line locations for Dockerfile and compose findings.

### 8. Generate policy

Start from a JSON report (step 7), then generate one or both engines:

```bash
escapearmed scan compose docker-compose.yml -f json -o report.json

# both engines
escapearmed gen-policy both --from report.json --kyverno-out policy.yaml --falco-out falco.yaml

# one engine
escapearmed gen-policy kyverno --from report.json --kyverno-out policy.yaml
escapearmed gen-policy falco --from report.json --falco-out falco.yaml

# every rule, Kyverno in audit mode
escapearmed gen-policy kyverno --all --action Audit --kyverno-out audit-policy.yaml
```

- `--from` takes any JSON report from `scan` or `prove`. `--all` emits every rule regardless of findings.
- `--action Enforce` (default) creates a `Deny` policy. `--action Audit` creates an `Audit` policy. Root and user namespace checks always go into a separate audit policy.
- Without `--kyverno-out` or `--falco-out`, output goes to the terminal.

Apply them:

```bash
kubectl apply -f policy.yaml
sudo falco -r /etc/falco/falco_rules.yaml -r falco.yaml
```

On the demo policy, the Kyverno CLI blocked all 10 intentionally bad test pods and allowed the hardened pod. Falco accepted the rules with `falco -V` (`Ok`). The check commands are in Setup step 6.

### 9. Use in CI

Upload SARIF to GitHub code scanning and fail the build on critical findings:

```yaml
# .github/workflows/escapearmed.yml
name: escapearmed
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/ritvikindupuri/EscapeArmed.git
      - run: escapearmed scan compose docker-compose.yml -f sarif -o escapearmed.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: escapearmed.sarif
      - run: escapearmed scan compose docker-compose.yml --fail-on critical
```

**Exit codes**

- `0` clean, or nothing at or above `--fail-on`.
- `2` a finding at or above `--fail-on`.
- `3` escape proven, with `--fail-on-escape`.
- `64` missing safety flags or targets.
- `65` target container not running.
- `70` Docker error.

### 10. Run the demo

```bash
./demo/run-demo.sh          # build the image, start 3 containers, scan and prove them, clean up
KEEP=1 ./demo/run-demo.sh   # same, but leave the containers running
```

- Writes every report and artifact to `examples/`, then checks that no canary file or scratch mount was left on the host.

### 11. List rules and CVEs

```bash
escapearmed rules
```

Prints all 25 rules with severity and CVE mapping. The full catalog, with rationale, is in [docs/TECHNICAL.md](https://github.com/ritvikindupuri/EscapeArmed/blob/main/docs/TECHNICAL.md).

### Known limits

- Version checks use the upstream version string. Distros that backport fixes may still show as affected, so treat EA015 as "check the package changelog".
- The runc race CVEs need a malicious image or config to trigger. EscapeArmed detects the setup and the missing mitigations, it does not run the race.
- containerd and CRI-O sockets speak gRPC, so the socket probe reports them as LIKELY, not PROVEN.
- Host side canary checks assume EscapeArmed runs on the Docker host. Use `--remote-daemon` otherwise.
- Falco rules are validated for syntax and fields with `falco -V`, not yet replayed against live events.

## Technical Documentation

- **Technical documentation:** internals, every rule with its rationale and CVE mapping, probe design and safety guarantees, output formats, limitations and testing.
  **[https://github.com/ritvikindupuri/EscapeArmed/blob/main/docs/TECHNICAL.md](https://github.com/ritvikindupuri/EscapeArmed/blob/main/docs/TECHNICAL.md)**
- **Demo security assessment report:** executive summary, scope, findings with evidence, policy validation and cleanup verification for the demo run.
  **[https://github.com/ritvikindupuri/EscapeArmed/blob/main/docs/DEMO-REPORT.md](https://github.com/ritvikindupuri/EscapeArmed/blob/main/docs/DEMO-REPORT.md)**

## License

MIT. See [LICENSE](LICENSE).
