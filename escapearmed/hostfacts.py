"""Collect facts about the container host: engine, runc, NVIDIA toolkit, socket."""

from __future__ import annotations

import grp
import os
import re
import shutil
import socket
import subprocess
from typing import Dict

from .docker import Docker, DockerError


def _cmd(args) -> str:
    if not shutil.which(args[0]):
        return ""
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def collect(docker: Docker) -> Dict:
    facts: Dict = {"hostname": socket.gethostname()}
    try:
        info = docker.info()
        facts["engine_version"] = info.get("ServerVersion", "")
        facts["security_options"] = info.get("SecurityOptions") or []
        facts["cgroup_version"] = info.get("CgroupVersion", "")
        facts["default_runtime"] = info.get("DefaultRuntime", "")
        facts["runtimes"] = sorted((info.get("Runtimes") or {}).keys())
        facts["runc_commit"] = (info.get("RuncCommit") or {}).get("ID", "")
        facts["kernel"] = info.get("KernelVersion", "")
    except DockerError as exc:
        facts["docker_error"] = str(exc)
    runc = _cmd(["runc", "--version"])
    m = re.search(r"runc version (\S+)", runc)
    facts["runc_version"] = m.group(1) if m else facts.get("runc_commit", "")
    nv = _cmd(["nvidia-ctk", "--version"]) or _cmd(["nvidia-container-cli", "--version"])
    m = re.search(r"(\d+\.\d+\.\d+)", nv)
    facts["nvidia_toolkit_version"] = m.group(1) if m else ""
    facts["nvidia_cuda_compat_hook_disabled"] = False
    for cfg in ("/etc/nvidia-container-runtime/config.toml", "/etc/nvidia-container-toolkit/config.toml"):
        try:
            with open(cfg) as fh:
                if re.search(r"^\s*disable-cuda-compat-lib-hook\s*=\s*true", fh.read(), re.M):
                    facts["nvidia_cuda_compat_hook_disabled"] = True
        except OSError:
            pass
    for path in ("/var/run/docker.sock", "/run/docker.sock"):
        if os.path.exists(path):
            st = os.stat(path)
            try:
                g = grp.getgrgid(st.st_gid)
                gname, members = g.gr_name, list(g.gr_mem)
            except KeyError:
                gname, members = str(st.st_gid), []
            facts["socket"] = {"path": path, "mode": st.st_mode & 0o777, "mode_octal": oct(st.st_mode & 0o777),
                               "group": gname, "group_members": members}
            break
    return facts
