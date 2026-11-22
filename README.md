# EscapeArmed

Container escape readiness scanner and prover.

EscapeArmed finds the configuration that makes a container escapable, then proves it with harmless canary probes instead of guessing from version numbers. It turns what it finds into a Kyverno policy, Falco rules and SARIF for CI.

## What it does

- **Static scan.** Reads a running container, an image, a Dockerfile, a compose file, or the host, and flags escape primitives: privileged mode, dangerous capabilities, runtime sockets, host path mounts, host PID/IPC/network namespaces, unconfined AppArmor or seccomp, host cgroup namespace, root without user namespaces, and runc race setups baked into images.
- **Active proof.** With explicit opt in, runs read-only or self-cleaning probes inside a container you own to show which escape steps actually work on this host.
- **Remediation output.** Generates a Kyverno `ValidatingPolicy` that blocks what was found, Falco rules that alert on the escape behavior, and SARIF 2.1.0 for code scanning.

## Why proof matters

- A scanner that only reads config says "SYS_ADMIN, medium risk". It cannot tell whether that is one command away from root on the host.
- In the demo below, a container that is **not privileged, has no socket and no host mounts** is proven escapable through the cgroup release_agent path, because it combines SYS_ADMIN, unconfined AppArmor and the host cgroup namespace.
- The same probes against a hardened container come back blocked, which is the evidence you want before closing a ticket.

## Attacks it targets

| CVE | Name | What EscapeArmed checks |
|---|---|---|
| [CVE-2025-31133](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2) | runc maskedPaths `/dev/null` symlink race (Nov 2025) | runc version on the host, `/dev` symlinks in image layers, Dockerfile steps that replace `/dev/null`, writable `core_pattern` (the end goal), user namespaces |
| [CVE-2025-52565](https://github.com/opencontainers/runc/security/advisories/GHSA-qw9x-cqr3-wc7r) | runc `/dev/console` bind mount race (Nov 2025) | runc version, `/dev/pts` and `/dev/console` symlinks in layers and Dockerfiles, user namespaces |
| [CVE-2025-52881](https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm) | runc LSM bypass through misdirected procfs writes (Nov 2025) | runc version, AppArmor state, writable `/proc/sysrq-trigger`, user namespaces |
| [CVE-2025-23266](https://nvidia.custhelp.com/app/answers/detail/a_id/5659) | NVIDIAScape, NVIDIA Container Toolkit `LD_PRELOAD` hook escape | `LD_PRELOAD` in image or container env, GPU workloads, toolkit version and the `disable-cuda-compat-lib-hook` mitigation |

Fixed versions: runc 1.2.8, 1.3.3 and 1.4.0-rc.3. NVIDIA Container Toolkit 1.17.8 and GPU Operator 25.3.2.

It also covers the classic primitives still used in the wild, such as exposed Docker sockets in cryptojacking campaigns, `--privileged` with `core_pattern`, release_agent, `/proc/1/root` with host PID, and raw disk access.

## Install

```bash
git clone https://github.com/ritvikindupuri/EscapeArmed
cd EscapeArmed
pip install .
escapearmed --version
```

- Python 3.9 or later. The only dependency is PyYAML.
- Needs the `docker` CLI for container, image and host scans. File scans work without Docker.
- Use `--docker "sudo docker"` or `ESCAPEARMED_DOCKER` if your user is not in the docker group.

## Usage

**scan** (static, safe to run anywhere)

```bash
escapearmed scan container web-1 api-1          # running containers, plus host checks
escapearmed scan all-containers                 # every running container
escapearmed scan image myorg/app:1.4            # image config and layer walk for runc race symlinks
escapearmed scan dockerfile Dockerfile
escapearmed scan compose docker-compose.yml
escapearmed scan host                           # runc, NVIDIA toolkit, userns, socket permissions
```

- `-f text|json|sarif` and `-o FILE` choose the output.
- `--emit-dir DIR` writes report.txt, report.json, escapearmed.sarif, kyverno-policy.yaml and falco-rules.yaml in one go.
- `--fail-on high` exits with code 2 when a finding at or above that severity exists, for CI gates.

**prove** (active, opt in)

```bash
escapearmed prove my-test-container --active --i-understand
escapearmed prove my-test-container --active --i-understand --yes --emit-dir out/   # automation
```

- Both `--active` and `--i-understand` are required. Without a TTY you must also pass `--yes`.
- Probes run as the container's configured user. `--as-root` models an attacker who already has root inside.
- `--fail-on-escape` exits with code 3 when an escape path is proven.

**gen-policy**

```bash
escapearmed scan compose docker-compose.yml -f json -o report.json
escapearmed gen-policy both --from report.json --kyverno-out policy.yaml --falco-out falco.yaml
escapearmed gen-policy kyverno --all --action Audit       # every rule, audit mode
```

**rules**

```bash
escapearmed rules        # list every detection rule and the CVEs it maps to
```

## Demo

The demo runs entirely inside a Kali Linux VM (Docker 28.5.2, runc 1.3.6, kernel 7.1.5, cgroup v2). It builds a plain Debian image and starts three containers from it.

- `ea-vulnapp`: privileged, host PID, SYS_ADMIN, Docker socket, host `/` read-only, and a writable host directory.
- `ea-sneaky`: not privileged. Only SYS_ADMIN, AppArmor unconfined and `--cgroupns=host`.
- `ea-hardened`: non-root, all capabilities dropped, read-only root, no-new-privileges.

```bash
./demo/run-demo.sh        # outputs land in examples/
```

**ea-sneaky, the interesting one**

```text
Summary
  CRITICAL 1  HIGH 2  MEDIUM 3  LOW 1  INFO 0
  Verdict: ESCAPABLE

Findings
  CRITICAL EA002 Dangerous Linux capability added [PROVEN]
           ea-sneaky: CAP_SYS_ADMIN added: mount, cgroup release_agent, many kernel interfaces.
           Fix: Drop ALL capabilities and add back only what is required. Never add SYS_ADMIN or SYS_MODULE.
  HIGH     EA009 AppArmor disabled (unconfined)
           ea-sneaky: AppArmor profile is unconfined.
           CVEs: CVE-2025-52881
           Fix: Use the default docker-default or runtime/default AppArmor profile.
  HIGH     EA012 Host cgroup namespace or writable cgroupfs [PROVEN]
           ea-sneaky: Host cgroup namespace plus SYS_ADMIN makes release_agent reachable.
           Fix: Use a private cgroup namespace (the default on cgroup v2) and never mount cgroupfs read-write.
  MEDIUM   EA013 Root in container without user namespace
           ea-sneaky: Process runs as UID 0.
           CVEs: CVE-2025-31133, CVE-2025-52565, CVE-2025-52881
           Fix: Run as a non-root USER, and enable user namespaces (rootless Docker, userns-remap, or Kubernetes hostUsers: false).
...
Active proof (canary probes)
  PROVEN   Dangerous effective capabilities
           CapEff=00000000a82425fb dangerous: SYS_ADMIN DAC_OVERRIDE
  NA       Runtime API reachable from container
           no runtime socket inside the container
  BLOCKED  Reach host filesystem through /proc/1/root
           PID 1 is sleep, 4 processes visible, host process tree not reachable
  BLOCKED  Host core_pattern writable (host code exec on crash)
           /proc/sys/kernel/core_pattern is read-only
  BLOCKED  Host sysrq-trigger writable
           /proc/sysrq-trigger is not writable
  PROVEN   mount(2) reachable
           mount(2) succeeded for a scratch tmpfs (unmounted)
  PROVEN   cgroup v1 release_agent escape reachable
           mounted a fresh cgroup v1 hierarchy, release_agent is writable (classic notify_on_release escape). Not written, unmounted.
  NA       Raw host block device readable
           no host block devices visible
  BLOCKED  Kernel module load capability
           CAP_SYS_MODULE not effective
  NA       LD_PRELOAD present (NVIDIAScape trigger)
           LD_PRELOAD not set
  INFO     identity: uid=0 uid_map=[0 0 4294967295]
  INFO     lsm: apparmor=[unconfined] seccomp_mode=2
  Cleanup: 0 canary file(s) removed, nothing left behind
```

**ea-vulnapp**

```text
Summary
  CRITICAL 3  HIGH 4  MEDIUM 2  LOW 0  INFO 0
  Verdict: ESCAPABLE
...
Active proof (canary probes)
  PROVEN   Dangerous effective capabilities
           CapEff=000001ffffffffff dangerous: SYS_ADMIN SYS_MODULE DAC_READ_SEARCH SYS_PTRACE SYS_RAWIO BPF SYS_BOOT NET_ADMIN DAC_OVERRIDE
  PROVEN   Runtime API reachable from container
           GET /version on /var/run/docker.sock answered: engine 28.5.2+dfsg4 API 1.51. Full daemon control from inside the container.
  PROVEN   Write to host filesystem through a bind mount
           canary written in container at /shared/.escapearmed-canary-b6cf9d1412c77781 appeared on the host at /tmp/escapearmed-demo-share/.escapearmed-canary-b6cf9d1412c77781 with the matching token
  PROVEN   Read host files through a bind mount
           read host hostname 'kali' through /host, matches this host. Host /etc/shadow is readable (content not read).
  PROVEN   Reach host filesystem through /proc/1/root
           read host hostname 'kali' through /proc/1/root, matches this host.
  PROVEN   Host core_pattern writable (host code exec on crash)
           /proc/sys/kernel/core_pattern is writable (current: core). Writing a |/path pipe here runs a host binary as root on the next crash. Not written.
  PROVEN   Host sysrq-trigger writable
           /proc/sysrq-trigger is writable, host can be crashed or rebooted from the container. Not written.
  PROVEN   mount(2) reachable
           mount(2) succeeded for a scratch tmpfs (unmounted)
  BLOCKED  cgroup v1 release_agent escape reachable
           new cgroup v1 hierarchy denied (private cgroup namespace), no writable release_agent. Becomes reachable with --cgroupns=host
  PROVEN   Raw host block device readable
           read the first sector of host block device /dev/vda (discarded)
  LIKELY   Kernel module load capability
           CAP_SYS_MODULE is effective, init_module would load host kernel code. Not attempted.
  NA       LD_PRELOAD present (NVIDIAScape trigger)
           LD_PRELOAD not set
  INFO     identity: uid=0 uid_map=[0 0 4294967295]
  INFO     lsm: apparmor=[unconfined] seccomp_mode=0
  Cleanup: 1 canary file(s) removed, nothing left behind
```

**ea-hardened**

```text
Summary
  CRITICAL 0  HIGH 0  MEDIUM 2  LOW 0  INFO 0
  Verdict: NO ESCAPE PATH PROVEN
```

Every probe in the hardened container came back BLOCKED or NA. See [examples/prove-hardened.txt](examples/prove-hardened.txt).

Full outputs: [examples/](examples/), including SARIF, JSON, and per container Kyverno and Falco files.

## Generated policy, verified

The generated artifacts are checked against the real engines, not just YAML parsing.

**Kyverno** (`tests/k8s/check-kyverno.sh`, Kyverno CLI v1.20.0). Each pod in `tests/k8s/violations/` carries one primitive and must be denied, the hardened pod must pass.

```text
BLOCKED  allow-priv-esc           EscapeArmed EA014
BLOCKED  apparmor-unconfined      EscapeArmed EA009
BLOCKED  docker-sock              EscapeArmed EA003
BLOCKED  host-etc                 EscapeArmed EA004/EA005
BLOCKED  host-pid                 EscapeArmed EA006/EA007/EA008
BLOCKED  host-root                EscapeArmed EA004/EA005
BLOCKED  ld-preload               EscapeArmed EA017
BLOCKED  privileged               EscapeArmed EA001
BLOCKED  seccomp-unconfined       EscapeArmed EA010
BLOCKED  sys-admin                EscapeArmed EA002
ALLOWED  good-pod
```

**Falco** (`tests/falco/check-falco.sh`, `falco -V` with falcosecurity/falco:0.45.2)

```text
/rules/escapearmed.yaml: Ok
```

- Kyverno output uses `policies.kyverno.io/v1` `ValidatingPolicy` with CEL. Kyverno 1.20 removed the legacy `ClusterPolicy` engine, so this is the format current clusters accept.
- Falco rules define their own `ea_*` macros, so they load with or without the default ruleset.

## Safety note on active mode

- Only run `prove` against containers you own or are authorized to test.
- Nothing is ever written to `core_pattern`, `sysrq-trigger`, `release_agent`, `binfmt_misc` or kernel modules. Those checks use `access()` style tests and report "Not written".
- The runtime socket check sends one read-only `GET /version`. It never creates containers.
- The only write is one canary file per writable host bind mount, containing a random token. The host side copy is verified, then removed, and the report says whether anything was left behind.
- Scratch mounts (a 1 MB tmpfs and an empty named cgroup v1 hierarchy) are unmounted by a trap, even on errors.
- Raw disk access is tested by reading the first 512 bytes into `/dev/null`.

## Rules

| ID | Severity | Rule |
|---|---|---|
| EA001 | critical | Privileged container |
| EA002 | high to critical | Dangerous capability added (SYS_ADMIN, SYS_MODULE, DAC_READ_SEARCH, SYS_PTRACE, BPF, ...) |
| EA003 | critical | Container runtime socket mounted |
| EA004 | critical | Host root filesystem mounted |
| EA005 | high | Sensitive host path mounted (/proc, /sys, /etc, /var/lib/docker, ...) |
| EA006 to EA008 | high, medium | Host PID, network, IPC namespaces |
| EA009, EA010 | high | AppArmor or seccomp unconfined |
| EA011 | high | Host device exposed |
| EA012 | medium | Host cgroup namespace or writable cgroupfs |
| EA013 | medium | Root in container without user namespace |
| EA014 | low | no-new-privileges not set |
| EA015 | critical | runc vulnerable to the November 2025 escapes |
| EA016 | critical | NVIDIA Container Toolkit vulnerable to NVIDIAScape |
| EA017 | high to critical | LD_PRELOAD in image or container env |
| EA018 | info | GPU workload on NVIDIA runtime |
| EA019 | critical | Image layers ship `/dev` or procfs symlinks |
| EA020 | high | Dockerfile step tampers with `/dev` or `/proc` |
| EA021 | high | `RUN --security=insecure` BuildKit entitlement |
| EA022 | medium | userns_mode: host |
| EA023 | medium to critical | Docker socket writable by non-root on the host |
| EA024 | medium | Daemon has no user namespace isolation |
| EA025 | medium | Writable host bind mount |

A finding whose escape step is proven is marked `[PROVEN]` and raised to at least high.

## How it works

- `escapearmed/sources/` normalizes docker inspect, image config and layers, Dockerfiles and compose files into one `ContainerSpec`.
- `escapearmed/analyzer.py` applies the rules to a spec and to host facts (runc and toolkit version ranges, daemon security options, socket permissions).
- `escapearmed/probe.sh` is a POSIX sh probe (busybox, dash, bash) piped into the container with `docker exec -i ... sh -s`. It prints one `EA|probe|STATUS|evidence` line per check.
- `escapearmed/prover.py` verifies canaries from the host side, matches hostnames read through mounts against the real host, cleans up, and computes the verdict.
- `escapearmed/generators/` builds Kyverno, Falco and SARIF output from the findings.

## Limitations

- Version checks use the upstream version string. Distros that backport fixes may still show as affected, so treat EA015 as "verify the package changelog".
- The runc race CVEs need a malicious image or config to trigger. EscapeArmed detects the setup and the missing mitigations, it does not run the race.
- containerd and CRI-O sockets speak gRPC, so the socket probe reports them as LIKELY rather than PROVEN.
- Host side canary verification assumes the scanner runs on the Docker host. Use `--remote-daemon` otherwise.
- Falco rules were validated for syntax and field names with `falco -V`, not yet replayed against live events.

## Tests

```bash
pip install .[test]
pytest -q
```

- 24 unit tests cover parsers, rule logic, version ranges, SARIF shape, policy generation and probe interpretation.
- `tests/k8s/check-kyverno.sh` and `tests/falco/check-falco.sh` validate generated policy against the real engines.

## License

MIT. See [LICENSE](LICENSE).
