"""docker compose file parser."""

from __future__ import annotations

from typing import Dict, List

import yaml

from ..models import ContainerSpec, Mount


def _line_index(text: str) -> List[str]:
    return text.splitlines()


def _find_line(lines: List[str], service: str, key: str) -> int:
    """Best effort line lookup: first `key:` after the `service:` header."""
    in_services, svc_line, svc_indent = False, None, 0
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("services:"):
            in_services = True
            continue
        if in_services and svc_line is None and stripped.rstrip(":") == service and stripped.endswith(":"):
            svc_line, svc_indent = idx, len(line) - len(line.lstrip())
            if not key:
                return idx
            continue
        if svc_line is not None:
            indent = len(line) - len(line.lstrip())
            if stripped and indent <= svc_indent:
                break
            if stripped.startswith(f"{key}:"):
                return idx
    return svc_line or 1


def _find_text(lines: List[str], start: int, needle: str) -> int:
    """First line at or after `start` (1 based) containing needle, else 0."""
    for idx in range(max(start, 1), len(lines) + 1):
        if needle in lines[idx - 1]:
            return idx
    return 0


def _parse_volume(vol, project_dir: str) -> Mount | None:
    if isinstance(vol, dict):
        src = str(vol.get("source", ""))
        tgt = str(vol.get("target", ""))
        vtype = vol.get("type", "volume")
        return Mount(source=src, target=tgt, read_only=bool(vol.get("read_only")), type=vtype)
    parts = str(vol).split(":")
    if len(parts) == 1:
        return Mount(source="", target=parts[0], type="volume")
    src, tgt = parts[0], parts[1]
    mode = parts[2] if len(parts) > 2 else "rw"
    ro = "ro" in mode.split(",")
    if src.startswith("/") or src.startswith(".") or src.startswith("~"):
        return Mount(source=src, target=tgt, read_only=ro, type="bind")
    return Mount(source=src, target=tgt, read_only=ro, type="volume")


def _env(value) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            out[str(k)] = "" if v is None else str(v)
    elif isinstance(value, list):
        for item in value:
            k, _, v = str(item).partition("=")
            out[k] = v
    return out


def parse_compose(text: str, path: str) -> List[ContainerSpec]:
    doc = yaml.safe_load(text) or {}
    services = doc.get("services") or {}
    lines = _line_index(text)
    specs: List[ContainerSpec] = []
    for svc_name, svc in services.items():
        svc = svc or {}
        spec = ContainerSpec(name=f"{path}#{svc_name}", source_type="compose", source_ref=path,
                             image=str(svc.get("image", "")))
        spec.privileged = bool(svc.get("privileged"))
        spec.cap_add = [str(c).upper().replace("CAP_", "", 1) for c in svc.get("cap_add") or []]
        spec.cap_drop = [str(c).upper().replace("CAP_", "", 1) for c in svc.get("cap_drop") or []]
        spec.mounts = [m for m in (_parse_volume(v, path) for v in svc.get("volumes") or []) if m]
        spec.pid_mode = str(svc.get("pid", "") or "")
        spec.network_mode = str(svc.get("network_mode", "") or "")
        spec.ipc_mode = str(svc.get("ipc", "") or "")
        spec.uts_mode = str(svc.get("uts", "") or "")
        spec.userns_mode = str(svc.get("userns_mode", "") or "")
        spec.cgroupns_mode = str(svc.get("cgroup", "") or "")
        spec.security_opt = [str(s) for s in svc.get("security_opt") or []]
        for so in spec.security_opt:
            if so.startswith("apparmor"):
                spec.apparmor_profile = so.split("=", 1)[-1].split(":", 1)[-1]
        spec.devices = [str(d).split(":")[0] for d in svc.get("devices") or []]
        spec.user = str(svc.get("user", "") or "")
        spec.env = _env(svc.get("environment"))
        spec.runtime = str(svc.get("runtime", "") or "")
        spec.readonly_rootfs = bool(svc.get("read_only"))
        reservations = (((svc.get("deploy") or {}).get("resources") or {}).get("reservations") or {})
        for dev in reservations.get("devices") or []:
            if dev.get("driver") == "nvidia" or "gpu" in (dev.get("capabilities") or []):
                spec.gpu_requested = True
        if "nvidia" in spec.runtime or svc.get("gpus"):
            spec.gpu_requested = True
        for key in ("privileged", "cap_add", "volumes", "pid", "network_mode", "ipc",
                    "security_opt", "devices", "user", "environment", "runtime", "userns_mode",
                    "cgroup", "deploy"):
            if key in svc:
                spec.lines[key] = _find_line(lines, svc_name, key)
        spec.lines["service"] = _find_line(lines, svc_name, "")
        for m in spec.mounts:
            needle = f"{m.source}:{m.target}" if m.source else m.target
            ln = _find_text(lines, spec.lines["service"], needle)
            if ln:
                spec.lines[f"vol:{m.target}"] = ln
        specs.append(spec)
    return specs
