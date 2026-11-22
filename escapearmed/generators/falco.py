"""Generate self-contained Falco rules for the escape behaviors that were found.

The file defines its own ea_* macros so it loads with or without the
default falco_rules.yaml."""

from __future__ import annotations

from typing import Iterable, List, Set

import yaml

from ..catalog import RULES
from ..models import Finding

MACROS = [
    {"macro": "ea_container", "condition": "(container.id != host and container.id != \"\")"},
    {"macro": "ea_open_write",
     "condition": "(evt.type in (open, openat, openat2) and evt.is_open_write=true and fd.num>=0)"},
    {"macro": "ea_open_read",
     "condition": "(evt.type in (open, openat, openat2) and evt.is_open_read=true and fd.num>=0)"},
    {"macro": "ea_spawned_process", "condition": "(evt.type in (execve, execveat))"},
]

OUT = "container=%container.name image=%container.image.repository proc=%proc.cmdline user=%user.name"


def _rule(name: str, desc: str, cond: str, output: str, priority: str, tags: List[str]) -> dict:
    return {"rule": name, "desc": desc, "condition": cond, "output": output,
            "priority": priority, "tags": ["escapearmed", "container_escape"] + tags}


def build_rules(keys: Set[str], host_mount_targets: List[str]) -> List[dict]:
    r: List[dict] = []
    if "core_pattern_write" in keys:
        r.append(_rule(
            "EscapeArmed Container Writes Host Kernel Hook",
            "A container process opened core_pattern, modprobe or binfmt_misc for writing. "
            "This is the end goal of CVE-2025-31133 style escapes and classic privileged escapes.",
            "ea_open_write and ea_container and (fd.name in (/proc/sys/kernel/core_pattern, "
            "/proc/sys/kernel/modprobe, /proc/sys/fs/binfmt_misc/register) or "
            "fd.name startswith /proc/sys/kernel/core_pattern)",
            "Container wrote a host kernel hook (file=%fd.name " + OUT + ")",
            "CRITICAL", ["mitre_privilege_escalation", "T1611", "CVE-2025-31133"]))
    if "sysrq_write" in keys:
        r.append(_rule(
            "EscapeArmed Container Writes sysrq-trigger",
            "A container opened /proc/sysrq-trigger for writing. CVE-2025-52881 shows runc writes "
            "can be redirected here.",
            "ea_open_write and ea_container and fd.name = /proc/sysrq-trigger",
            "Container opened sysrq-trigger for write (" + OUT + ")",
            "CRITICAL", ["T1611", "CVE-2025-52881"]))
    if "release_agent_write" in keys:
        r.append(_rule(
            "EscapeArmed Cgroup Release Agent Write",
            "A container wrote a cgroup v1 release_agent or notify_on_release file.",
            "ea_open_write and ea_container and (fd.name endswith /release_agent or "
            "fd.name endswith /notify_on_release)",
            "cgroup release_agent escape attempt (file=%fd.name " + OUT + ")",
            "CRITICAL", ["T1611"]))
    if "container_mount" in keys:
        r.append(_rule(
            "EscapeArmed Mount From Container",
            "A process inside a container called mount. Normal workloads do not mount filesystems.",
            "evt.type in (mount, fsmount, move_mount) and ea_container",
            "mount syscall inside container (" + OUT + ")",
            "WARNING", ["T1611"]))
    if "runtime_socket_access" in keys:
        r.append(_rule(
            "EscapeArmed Container Runtime Socket Connect",
            "A container connected to the Docker, containerd or CRI-O socket.",
            "evt.type = connect and ea_container and fd.typechar = u and "
            "(fd.name contains docker.sock or fd.name contains containerd.sock or "
            "fd.name contains crio.sock or fd.name contains podman.sock)",
            "Container connected to runtime socket (socket=%fd.name " + OUT + ")",
            "CRITICAL", ["T1610", "T1611"]))
    if "proc_root_access" in keys:
        r.append(_rule(
            "EscapeArmed Host Root Via proc PID 1",
            "A container read through /proc/1/root or ran nsenter, the host PID namespace escape path.",
            "ea_container and ((ea_open_read and fd.name startswith /proc/1/root/) or "
            "(ea_spawned_process and proc.name = nsenter))",
            "Host filesystem reached through /proc/1 (file=%fd.name " + OUT + ")",
            "CRITICAL", ["T1611"]))
    if "host_sensitive_write" in keys:
        targets = sorted(set(t.rstrip("/") for t in host_mount_targets if t and t != "/")) or ["/host"]
        prefixes = " or ".join(f"fd.name startswith {t}/" for t in targets)
        r.append(_rule(
            "EscapeArmed Write Through Host Mount",
            "A container wrote into a host bind mount that EscapeArmed flagged as sensitive.",
            f"ea_open_write and ea_container and ({prefixes})",
            "Write into sensitive host mount (file=%fd.name " + OUT + ")",
            "ERROR", ["T1611"]))
    if "raw_disk_read" in keys:
        r.append(_rule(
            "EscapeArmed Raw Host Disk Access",
            "A container opened a host block device.",
            "(ea_open_read or ea_open_write) and ea_container and fd.typechar = b",
            "Raw block device opened from container (dev=%fd.name " + OUT + ")",
            "CRITICAL", ["T1611", "T1006"]))
    if "kernel_module_load" in keys:
        r.append(_rule(
            "EscapeArmed Kernel Module Load From Container",
            "A container called init_module or finit_module.",
            "evt.type in (init_module, finit_module) and ea_container",
            "Kernel module load from container (" + OUT + ")",
            "CRITICAL", ["T1611", "T1547.006"]))
    if "nvidia_hook_preload" in keys:
        r.append(_rule(
            "EscapeArmed NVIDIAScape Hook With LD_PRELOAD",
            "An NVIDIA Container Toolkit hook started with LD_PRELOAD in its environment "
            "(CVE-2025-23266).",
            "ea_spawned_process and proc.name in (nvidia-ctk, nvidia-container-runtime-hook, "
            "nvidia-container-cli) and proc.env contains \"LD_PRELOAD=\"",
            "NVIDIA hook executed with LD_PRELOAD (env=%proc.env cmd=%proc.cmdline)",
            "CRITICAL", ["T1611", "CVE-2025-23266"]))
    return r


ALL_KEYS = {"core_pattern_write", "sysrq_write", "release_agent_write", "container_mount",
            "runtime_socket_access", "proc_root_access", "host_sensitive_write", "raw_disk_read",
            "kernel_module_load", "nvidia_hook_preload"}


def keys_from_findings(findings: Iterable[Finding]) -> Set[str]:
    keys: Set[str] = set()
    for f in findings:
        rule = RULES.get(f.rule_id)
        if rule:
            keys.update(rule.falco)
    return keys


def generate(findings: List[Finding], all_rules: bool = False) -> str:
    keys = ALL_KEYS if all_rules else keys_from_findings(findings)
    targets = [f.evidence.get("container_path", "") for f in findings
               if f.rule_id in ("EA004", "EA005", "EA025")]
    rules = build_rules(keys, targets)
    doc = [{"required_engine_version": "0.31.0"}] + MACROS + rules
    header = "# Generated by EscapeArmed. Load with: falco -r escapearmed_falco_rules.yaml\n"
    return header + yaml.safe_dump(doc, sort_keys=False, width=110)
