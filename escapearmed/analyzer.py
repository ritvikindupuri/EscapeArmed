"""Turn a ContainerSpec (or host facts) into findings."""

from __future__ import annotations

import os
import re
import stat
from typing import Dict, List, Optional, Tuple

from .catalog import (CAP_REASON, DANGEROUS_CAPS, RULES, RUNTIME_SOCKETS,
                      SENSITIVE_HOST_PATHS)
from .models import ContainerSpec, Finding

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _finding(rule_id: str, spec_name: str, detail: str, *, severity: Optional[str] = None,
             evidence: Optional[dict] = None, file: Optional[str] = None,
             line: Optional[int] = None, extra_cves: Optional[List[str]] = None) -> Finding:
    rule = RULES[rule_id]
    cves = list(dict.fromkeys(list(rule.cves) + list(extra_cves or [])))
    return Finding(rule_id=rule_id, title=rule.title, severity=severity or rule.severity,
                   target=spec_name, detail=detail, cves=cves, remediation=rule.remediation,
                   evidence=evidence or {}, file=file, line=line)


def _is_root(user: str) -> bool:
    u = (user or "").split(":")[0].strip()
    return u in ("", "0", "root")


def _seccomp_unconfined(spec: ContainerSpec) -> bool:
    return any(re.match(r"seccomp[=:]unconfined", so) for so in spec.security_opt)


def _apparmor_unconfined(spec: ContainerSpec) -> bool:
    if spec.apparmor_profile == "unconfined":
        return True
    return any(re.match(r"apparmor[=:]unconfined", so) for so in spec.security_opt)


def _norm(path: str) -> str:
    path = os.path.normpath(path) if path else path
    return path


def analyze_spec(spec: ContainerSpec) -> List[Finding]:
    f: List[Finding] = []
    file = spec.source_ref if spec.source_type in ("dockerfile", "compose") else None
    L = spec.lines.get

    if spec.privileged:
        f.append(_finding("EA001", spec.name, "Container runs with --privileged.",
                          evidence={"privileged": True}, file=file, line=L("privileged")))

    for cap in spec.cap_add:
        if cap in DANGEROUS_CAPS:
            f.append(_finding("EA002", spec.name,
                              f"CAP_{cap} added: {CAP_REASON.get(cap, '')}.",
                              severity=DANGEROUS_CAPS[cap], evidence={"capability": cap},
                              file=file, line=L("cap_add")))

    for m in spec.mounts:
        if not m.is_host_path:
            continue
        src = _norm(m.source)
        mode = "read-only" if m.read_only else "read-write"
        ev = {"host_path": src, "container_path": m.target, "mode": mode}
        if src in RUNTIME_SOCKETS or src.endswith(".sock") and any(
                s in src for s in ("docker", "containerd", "crio", "podman")):
            f.append(_finding("EA003", spec.name,
                              f"Runtime socket {src} mounted at {m.target} ({mode}). "
                              "Read-only does not help, the API is still fully usable.",
                              evidence=ev, file=file, line=L(f"vol:{m.target}") or L("volumes")))
        elif src == "/":
            f.append(_finding("EA004", spec.name, f"Host / mounted at {m.target} ({mode}).",
                              severity="critical" if not m.read_only else "high",
                              evidence=ev, file=file, line=L(f"vol:{m.target}") or L("volumes")))
        else:
            for sens in SENSITIVE_HOST_PATHS:
                if src == sens or src.startswith(sens + "/"):
                    sev = "high" if not m.read_only else "medium"
                    if src.startswith("/sys/fs/cgroup") and not m.read_only:
                        f.append(_finding("EA012", spec.name,
                                          f"Writable cgroupfs {src} mounted at {m.target}.",
                                          evidence=ev, file=file, line=L(f"vol:{m.target}") or L("volumes")))
                    f.append(_finding("EA005", spec.name,
                                      f"Host {src} mounted at {m.target} ({mode}).",
                                      severity=sev, evidence=ev, file=file, line=L(f"vol:{m.target}") or L("volumes")))
                    break
            else:
                if not m.read_only and not src.endswith(".sock"):
                    f.append(_finding("EA025", spec.name, f"Host {src} mounted read-write at {m.target}.",
                                      evidence=ev, file=file, line=L(f"vol:{m.target}") or L("volumes")))

    if spec.pid_mode == "host":
        f.append(_finding("EA006", spec.name, "pid: host shares the host PID namespace.",
                          file=file, line=L("pid")))
    if spec.network_mode == "host":
        f.append(_finding("EA007", spec.name, "network_mode: host shares the host network.",
                          file=file, line=L("network_mode")))
    if spec.ipc_mode == "host":
        f.append(_finding("EA008", spec.name, "ipc: host shares host IPC.",
                          file=file, line=L("ipc")))
    if _apparmor_unconfined(spec) and not spec.privileged:
        f.append(_finding("EA009", spec.name, "AppArmor profile is unconfined.",
                          file=file, line=L("security_opt")))
    if _seccomp_unconfined(spec) and not spec.privileged:
        f.append(_finding("EA010", spec.name, "Seccomp profile is unconfined.",
                          file=file, line=L("security_opt")))
    if spec.devices:
        f.append(_finding("EA011", spec.name, f"Host devices mapped: {', '.join(spec.devices)}.",
                          evidence={"devices": spec.devices}, file=file, line=L("devices")))
    if spec.cgroupns_mode == "host" and (spec.privileged or "SYS_ADMIN" in spec.cap_add):
        f.append(_finding("EA012", spec.name,
                          "Host cgroup namespace plus SYS_ADMIN makes release_agent reachable.",
                          file=file, line=L("cgroup")))
    if spec.userns_mode == "host":
        f.append(_finding("EA022", spec.name, "userns_mode: host disables user namespace remap.",
                          file=file, line=L("userns_mode")))

    # Root without userns: relevant for runtime and declarative sources
    if spec.source_type in ("container", "compose", "dockerfile", "image") and _is_root(spec.user):
        where = "No USER instruction, the image runs as root." if spec.source_type in (
            "dockerfile", "image") else "Process runs as UID 0."
        f.append(_finding("EA013", spec.name, where, severity="medium" if not spec.privileged else "high",
                          file=file, line=L("user")))

    if spec.source_type in ("container", "compose") and not spec.privileged and not any(
            "no-new-privileges" in so for so in spec.security_opt):
        f.append(_finding("EA014", spec.name, "no-new-privileges is not set.", file=file,
                          line=L("security_opt") or L("service")))

    if "LD_PRELOAD" in spec.env:
        sev = "critical" if spec.gpu_requested else "high"
        f.append(_finding("EA017", spec.name,
                          f"LD_PRELOAD={spec.env['LD_PRELOAD']!r} is set"
                          + (" on a GPU workload, the exact NVIDIAScape trigger." if spec.gpu_requested
                             else "."),
                          severity=sev, evidence={"LD_PRELOAD": spec.env["LD_PRELOAD"]},
                          file=file, line=L("env:LD_PRELOAD") or L("environment")))
    if spec.gpu_requested:
        f.append(_finding("EA018", spec.name, "Workload requests NVIDIA GPUs.", file=file,
                          line=L("deploy") or L("runtime")))

    # Dockerfile specific
    for lineno, cmd in spec.extra.get("dev_tamper", []):
        f.append(_finding("EA020", spec.name, f"RUN modifies /dev or links into /proc: {cmd[:120]}",
                          evidence={"instruction": cmd[:300]}, file=file, line=lineno))
    if "insecure_build" in spec.lines:
        f.append(_finding("EA021", spec.name, "RUN --security=insecure runs this step privileged.",
                          file=file, line=spec.lines["insecure_build"]))

    # Image layer facts
    for hit in spec.extra.get("layer_hits", []):
        f.append(_finding("EA019", spec.name,
                          f"{hit['kind']} {hit['path']} -> {hit['link'] or '(device)'} in layer "
                          f"{hit['layer'][:24]}.", evidence=hit))
    if file:
        for item in f:
            if item.line is None:
                item.line = L("service") or 1
    return f


# ---------------------------------------------------------------- host checks

def parse_semver(text: str) -> Optional[Tuple[int, int, int, str]]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)(?:[-~]?(rc\.?\d+))?", text or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), (m.group(4) or "")


def runc_vulnerable(version: str) -> Optional[bool]:
    """True if runc is affected by CVE-2025-31133/52565/52881.

    Fixed: 1.2.8, 1.3.3, 1.4.0-rc.3. Distros that backport fixes keep the
    upstream version string, so a True result should be read as 'needs review'
    when the package comes from a distro."""
    v = parse_semver(version)
    if not v:
        return None
    major, minor, patch, rc = v
    if major != 1:
        return major < 1
    if minor < 2:
        return True
    if minor == 2:
        return patch < 8
    if minor == 3:
        return patch < 3
    if minor == 4 and patch == 0 and rc:
        num = int(re.sub(r"\D", "", rc) or 0)
        return num < 3
    return False


def nvidia_toolkit_vulnerable(version: str) -> Optional[bool]:
    v = parse_semver(version)
    if not v:
        return None
    return (v[0], v[1], v[2]) < (1, 17, 8)


def analyze_host(facts: Dict) -> List[Finding]:
    f: List[Finding] = []
    host = facts.get("hostname", "host")
    runc = facts.get("runc_version", "")
    vuln = runc_vulnerable(runc)
    if vuln:
        f.append(_finding("EA015", host, f"runc {runc} is in the affected range.",
                          evidence={"runc_version": runc}))
    nv = facts.get("nvidia_toolkit_version")
    if nv and nvidia_toolkit_vulnerable(nv):
        mitigated = facts.get("nvidia_cuda_compat_hook_disabled")
        f.append(_finding("EA016", host, f"NVIDIA Container Toolkit {nv} is older than 1.17.8"
                          + (" (cuda-compat hook disabled, partial mitigation)." if mitigated else "."),
                          severity="high" if mitigated else None,
                          evidence={"nvidia_toolkit_version": nv, "hook_disabled": bool(mitigated)}))
    opts = " ".join(facts.get("security_options", []))
    if "userns" not in opts and "rootless" not in opts:
        f.append(_finding("EA024", host, "Docker daemon runs rootful without userns-remap.",
                          evidence={"security_options": facts.get("security_options", [])}))
    sock = facts.get("socket")
    if sock and sock.get("mode") is not None:
        mode = sock["mode"]
        if mode & stat.S_IWOTH:
            f.append(_finding("EA023", host, f"{sock['path']} is world writable.",
                              severity="critical", evidence=sock))
        elif mode & stat.S_IWGRP and sock.get("group_members"):
            f.append(_finding("EA023", host,
                              f"{sock['path']} is writable by group {sock.get('group')} "
                              f"({', '.join(sock['group_members'])}). Each member is effectively root.",
                              severity="medium", evidence=sock))
    return f
