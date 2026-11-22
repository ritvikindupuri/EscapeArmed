"""Walk the layers of a saved image looking for the filesystem setup that the
November 2025 runc mount races need: symlinks planted at /dev paths, or
symlinks that point into /proc."""

from __future__ import annotations

import io
import json
import os
import tarfile
import tempfile
from typing import Dict, List

from ..docker import Docker

WATCH_DEV = {"dev/null", "dev/console", "dev/pts", "dev/ptmx", "dev/zero", "dev/full",
             "dev/random", "dev/urandom", "dev/tty", "dev/shm"}


def _scan_layer(fileobj, layer_name: str, hits: List[Dict[str, str]]) -> None:
    with tarfile.open(fileobj=fileobj, mode="r:*") as layer:
        for member in layer:
            name = member.name.lstrip("./")
            if member.issym() or member.islnk():
                link = member.linkname
                if name in WATCH_DEV or (name.startswith("dev/") and name.count("/") == 1):
                    hits.append({"layer": layer_name, "path": "/" + name, "kind": "dev-symlink",
                                 "link": link})
                elif link.startswith("/proc/") or "/proc/sys" in link or "proc/self" in link:
                    hits.append({"layer": layer_name, "path": "/" + name, "kind": "proc-symlink",
                                 "link": link})
            elif member.ischr() or member.isblk():
                hits.append({"layer": layer_name, "path": "/" + name, "kind": "device-node",
                             "link": ""})


def scan_image_layers(docker: Docker, ref: str) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="escapearmed-") as tmp:
        tar_path = os.path.join(tmp, "image.tar")
        docker.save_image(ref, tar_path)
        with tarfile.open(tar_path) as outer:
            names = outer.getnames()
            layers: List[str] = []
            if "manifest.json" in names:
                manifest = json.load(outer.extractfile("manifest.json"))
                for entry in manifest:
                    layers.extend(entry.get("Layers") or [])
            for layer_name in layers:
                member = outer.getmember(layer_name)
                data = outer.extractfile(member)
                if data is None:
                    continue
                _scan_layer(io.BytesIO(data.read()), layer_name, hits)
    return hits
