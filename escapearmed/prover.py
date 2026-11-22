"""Active canary proofs. Runs probe.sh inside an opted-in container and turns
its output into proven / blocked escape paths. Every probe is read-only or
self-cleaning, and host side verification only checks for a canary file."""

from __future__ import annotations

import os
import secrets
import shlex
import socket
from importlib import resources
from typing import Dict, List, Tuple

from .docker import Docker, DockerError
from .models import ContainerSpec, ProbeResult
from .catalog import RUNC_NOV_2025, NVIDIASCAPE

PROBE_META: Dict[str, Tuple[str, List[str], List[str]]] = {
    # probe id: (title, rule ids it confirms, cves)
    "runtime_socket": ("Runtime API reachable from container", ["EA003"], []),
    "host_write": ("Write to host filesystem through a bind mount", ["EA025", "EA004", "EA005"], []),
    "host_read": ("Read host files through a bind mount", ["EA004", "EA005"], []),
    "host_pid": ("Reach host filesystem through /proc/1/root", ["EA006"], []),
    "core_pattern": ("Host core_pattern writable (host code exec on crash)", ["EA001"], RUNC_NOV_2025[:1]),
    "sysrq": ("Host sysrq-trigger writable", ["EA001"], ["CVE-2025-52881"]),
    "mount": ("mount(2) reachable", ["EA001", "EA002", "EA010"], []),
    "release_agent": ("cgroup v1 release_agent escape reachable", ["EA001", "EA002", "EA012"], []),
    "raw_disk": ("Raw host block device readable", ["EA001", "EA011"], []),
    "kernel_module": ("Kernel module load capability", ["EA002"], []),
    "caps": ("Dangerous effective capabilities", ["EA001", "EA002"], []),
    "ld_preload": ("LD_PRELOAD present (NVIDIAScape trigger)", ["EA017"], NVIDIASCAPE),
}

PROBE_FINAL_STATUS = {"PROVEN", "LIKELY", "BLOCKED", "NA", "ERROR"}


def load_probe_script() -> str:
    return resources.files("escapearmed").joinpath("probe.sh").read_text()


def plan(spec: ContainerSpec) -> Dict[str, List[str]]:
    write_dirs, read_roots, sockets = [], [], []
    for m in spec.mounts:
        if not m.is_host_path:
            continue
        if m.source.endswith(".sock"):
            sockets.append(m.target)
            continue
        if not m.read_only:
            write_dirs.append(m.target)
        if m.source in ("/", "/etc") or m.source.rstrip("/") == "":
            read_roots.append(m.target)
    return {"write": write_dirs, "read": read_roots, "sockets": sockets,
            "cgroupns": spec.cgroupns_mode or ""}


def build_script(token: str, p: Dict[str, List[str]]) -> str:
    header = (
        f"EA_TOKEN={shlex.quote(token)}\n"
        f"EA_WRITE_DIRS={shlex.quote(' '.join(p['write']))}\n"
        f"EA_READ_ROOTS={shlex.quote(' '.join(p['read']))}\n"
        f"EA_SOCKETS={shlex.quote(' '.join(p['sockets']))}\n"
        f"EA_CGROUPNS={shlex.quote(p.get('cgroupns', ''))}\n"
    )
    return header + load_probe_script()


def parse_probe_output(text: str) -> List[Tuple[str, str, str]]:
    rows = []
    for line in text.splitlines():
        if not line.startswith("EA|"):
            continue
        parts = line.split("|", 3)
        if len(parts) == 4:
            rows.append((parts[1], parts[2], parts[3]))
    return rows


def _host_hostname() -> str:
    try:
        with open("/etc/hostname") as fh:
            return fh.read().strip()
    except OSError:
        return socket.gethostname()


def _mount_source(spec: ContainerSpec, target: str) -> str:
    for m in spec.mounts:
        if m.target == target:
            return m.source
    return ""


def interpret(rows: List[Tuple[str, str, str]], spec: ContainerSpec, token: str,
              local_host: bool = True) -> Tuple[List[ProbeResult], List[str], Dict[str, str]]:
    """Return probe results, the container paths of canaries to clean, and info rows."""
    results: List[ProbeResult] = []
    cleanup: List[str] = []
    info: Dict[str, str] = {}
    hostname = _host_hostname()

    def add(pid: str, status: str, evidence: str) -> None:
        title, rules, cves = PROBE_META.get(pid, (pid, [], []))
        results.append(ProbeResult(pid, title, status, evidence, rules, cves))

    for pid, status, ev in rows:
        if status == "INFO":
            info[pid] = ev
            continue
        if pid == "host_write" and status == "WROTE":
            target_dir, path = ev.split("|", 1)
            cleanup.append(path)
            src = _mount_source(spec, target_dir)
            host_file = os.path.join(src, os.path.basename(path)) if src else ""
            if local_host and host_file:
                try:
                    with open(host_file) as fh:
                        content = fh.read()
                    if token in content:
                        add(pid, "PROVEN", f"canary written in container at {path} appeared on the "
                                           f"host at {host_file} with the matching token")
                    else:
                        add(pid, "LIKELY", f"{host_file} exists but token did not match")
                except PermissionError:
                    add(pid, "LIKELY", f"canary written at {path}, host copy {host_file} exists "
                                       "but is not readable by the scanner user")
                except FileNotFoundError:
                    add(pid, "BLOCKED", f"canary written at {path} but not visible on host at {host_file}")
            else:
                add(pid, "LIKELY", f"canary written at {path} (host side not verified, remote daemon)")
            continue
        if pid in ("host_read", "host_pid") and status == "READ":
            root, seen_host, third = (ev.split("|") + ["", ""])[:3]
            if local_host and seen_host == hostname:
                extra = ""
                if pid == "host_read" and third == "yes":
                    extra = " Host /etc/shadow is readable (content not read)."
                add(pid, "PROVEN", f"read host hostname {seen_host!r} through {root}, matches this host.{extra}")
            else:
                add(pid, "LIKELY", f"read hostname {seen_host!r} through {root}")
            continue
        if status in PROBE_FINAL_STATUS:
            add(pid, status, ev)
    return results, cleanup, info


def verdict(results: List[ProbeResult]) -> str:
    escape = {"runtime_socket", "host_write", "host_pid", "core_pattern", "release_agent",
              "raw_disk", "host_read"}
    if any(r.status == "PROVEN" and r.probe_id in escape for r in results):
        return "ESCAPABLE"
    if any(r.status in ("PROVEN", "LIKELY") for r in results if r.probe_id != "ld_preload"):
        return "AT RISK"
    return "NO ESCAPE PATH PROVEN"


def run_proof(docker: Docker, container: str, spec: ContainerSpec, as_root: bool = False,
              local_host: bool = True) -> Dict:
    token = secrets.token_hex(8)
    p = plan(spec)
    script = build_script(token, p)
    args = ["exec", "-i"]
    if as_root:
        args += ["-u", "0"]
    args += [container, "sh", "-s"]
    proc = docker.run(args, input_data=script.encode(), timeout=180, check=False)
    output = proc.stdout.decode(errors="replace")
    if not output.strip():
        raise DockerError(f"probe produced no output: {proc.stderr.decode(errors='replace').strip()}")
    rows = parse_probe_output(output)
    results, cleanup, info = interpret(rows, spec, token, local_host=local_host)
    cleaned: List[str] = []
    if cleanup:
        rm = "rm -f " + " ".join(shlex.quote(c) for c in cleanup)
        crm = docker.run(["exec", "-i"] + (["-u", "0"] if as_root else []) + [container, "sh", "-c", rm],
                         check=False)
        if crm.returncode == 0:
            cleaned = cleanup
    return {
        "container": container,
        "token": token,
        "plan": p,
        "info": info,
        "results": [r.to_dict() for r in results],
        "verdict": verdict(results),
        "canaries_cleaned": cleaned,
        "canaries_left": [c for c in cleanup if c not in cleaned],
    }
