"""Thin wrapper around the docker CLI. Using the CLI (not the SDK) keeps the
tool dependency free and makes it work with any context or DOCKER_HOST."""

from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any, List, Optional


class DockerError(RuntimeError):
    pass


class Docker:
    def __init__(self, cmd: str = "docker"):
        self.base = shlex.split(cmd)

    def run(self, args: List[str], input_data: Optional[bytes] = None, timeout: int = 300,
            check: bool = True) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(self.base + args, input=input_data, capture_output=True,
                                  timeout=timeout)
        except FileNotFoundError as exc:
            raise DockerError(f"docker CLI not found: {self.base[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise DockerError(f"docker {' '.join(args[:2])} timed out") from exc
        if check and proc.returncode != 0:
            raise DockerError(proc.stderr.decode(errors="replace").strip() or
                              f"docker {' '.join(args)} failed")
        return proc

    def json(self, args: List[str]) -> Any:
        out = self.run(args).stdout.decode()
        return json.loads(out)

    def inspect_container(self, ref: str) -> dict:
        data = self.json(["container", "inspect", ref])
        if not data:
            raise DockerError(f"no such container: {ref}")
        return data[0]

    def inspect_image(self, ref: str) -> dict:
        data = self.json(["image", "inspect", ref])
        if not data:
            raise DockerError(f"no such image: {ref}")
        return data[0]

    def info(self) -> dict:
        return self.json(["info", "--format", "{{json .}}"])

    def version(self) -> dict:
        return self.json(["version", "--format", "{{json .}}"])

    def exec_script(self, container: str, script: str, timeout: int = 120) -> str:
        proc = self.run(["exec", "-i", "-u", "0", container, "sh", "-s"],
                        input_data=script.encode(), timeout=timeout, check=False)
        if proc.returncode not in (0,) and not proc.stdout:
            raise DockerError(proc.stderr.decode(errors="replace").strip())
        return proc.stdout.decode(errors="replace")

    def save_image(self, ref: str, dest: str) -> None:
        self.run(["image", "save", "-o", dest, ref], timeout=900)
