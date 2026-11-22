"""Normalize `docker inspect` output (containers and images) into ContainerSpec."""

from __future__ import annotations

from typing import Dict, List

from ..models import ContainerSpec, Mount


def env_list_to_dict(env: List[str] | None) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in env or []:
        key, _, val = item.partition("=")
        out[key] = val
    return out


def _norm_cap(cap: str) -> str:
    cap = cap.upper()
    return cap[4:] if cap.startswith("CAP_") else cap


def from_container_inspect(data: dict) -> ContainerSpec:
    hc = data.get("HostConfig") or {}
    cfg = data.get("Config") or {}
    name = (data.get("Name") or data.get("Id", "")[:12]).lstrip("/")
    mounts: List[Mount] = []
    for m in data.get("Mounts") or []:
        mounts.append(Mount(source=m.get("Source", ""), target=m.get("Destination", ""),
                            read_only=not m.get("RW", True), type=m.get("Type", "bind")))
    devices = [d.get("PathOnHost", "") for d in hc.get("Devices") or []]
    gpu = False
    for req in hc.get("DeviceRequests") or []:
        caps = [c for group in (req.get("Capabilities") or []) for c in group]
        if req.get("Driver") == "nvidia" or "gpu" in caps:
            gpu = True
    env = env_list_to_dict(cfg.get("Env"))
    runtime = hc.get("Runtime", "") or ""
    if "nvidia" in runtime or env.get("NVIDIA_VISIBLE_DEVICES", "void") not in ("", "void", "none"):
        gpu = True
    return ContainerSpec(
        name=name,
        source_type="container",
        source_ref=name,
        image=cfg.get("Image", ""),
        privileged=bool(hc.get("Privileged")),
        cap_add=[_norm_cap(c) for c in hc.get("CapAdd") or []],
        cap_drop=[_norm_cap(c) for c in hc.get("CapDrop") or []],
        mounts=mounts,
        pid_mode=hc.get("PidMode", "") or "",
        network_mode=hc.get("NetworkMode", "") or "",
        ipc_mode=hc.get("IpcMode", "") or "",
        uts_mode=hc.get("UTSMode", "") or "",
        userns_mode=hc.get("UsernsMode", "") or "",
        cgroupns_mode=hc.get("CgroupnsMode", "") or "",
        security_opt=list(hc.get("SecurityOpt") or []),
        apparmor_profile=data.get("AppArmorProfile", "") or "",
        devices=devices,
        user=cfg.get("User", "") or "",
        env=env,
        runtime=runtime,
        gpu_requested=gpu,
        readonly_rootfs=bool(hc.get("ReadonlyRootfs")),
        extra={"state": (data.get("State") or {}).get("Status", "")},
    )


def from_image_inspect(data: dict, ref: str) -> ContainerSpec:
    cfg = data.get("Config") or {}
    env = env_list_to_dict(cfg.get("Env"))
    labels = cfg.get("Labels") or {}
    gpu = "NVIDIA_VISIBLE_DEVICES" in env or any(k.startswith("com.nvidia") for k in labels)
    return ContainerSpec(
        name=ref,
        source_type="image",
        source_ref=ref,
        image=ref,
        user=cfg.get("User", "") or "",
        env=env,
        gpu_requested=gpu,
        extra={"volumes": sorted((cfg.get("Volumes") or {}).keys()), "labels": labels},
    )
