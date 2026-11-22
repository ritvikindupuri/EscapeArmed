"""Static Dockerfile parser. It only needs to understand the instructions that
carry escape signal: FROM, USER, ENV, RUN, VOLUME and LABEL."""

from __future__ import annotations

import re
import shlex
from typing import List, Tuple

from ..models import ContainerSpec

DEV_TAMPER = re.compile(
    r"(ln\s+-[a-zA-Z]*s[a-zA-Z]*\s+\S+\s+/dev/(null|console|pts|ptmx|zero|full|random|urandom|tty)\b)"
    r"|(\brm\s+(-[a-zA-Z]+\s+)*/dev/(null|console)\b)"
    r"|(ln\s+-[a-zA-Z]*s[a-zA-Z]*\s+/proc/)"
    r"|(mknod\s+)"
)


def _logical_lines(text: str) -> List[Tuple[int, str]]:
    """Join backslash continued lines, keep the first physical line number."""
    out: List[Tuple[int, str]] = []
    buf, start = "", 0
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if not buf:
            start = idx
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        out.append((start, buf.strip()))
        buf = ""
    if buf:
        out.append((start, buf.strip()))
    return out


def _parse_env(args: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    try:
        tokens = shlex.split(args)
    except ValueError:
        tokens = args.split()
    if tokens and "=" not in tokens[0]:
        # legacy form: ENV KEY value with spaces
        key, _, val = args.strip().partition(" ")
        return [(key, val.strip())]
    for tok in tokens:
        key, _, val = tok.partition("=")
        pairs.append((key, val))
    return pairs


def parse_dockerfile(text: str, path: str) -> ContainerSpec:
    spec = ContainerSpec(name=path, source_type="dockerfile", source_ref=path)
    runs: List[Tuple[int, str]] = []
    froms: List[Tuple[int, str]] = []
    for lineno, line in _logical_lines(text):
        instr, _, args = line.partition(" ")
        instr = instr.upper()
        args = args.strip()
        if instr == "FROM":
            image = args.split()[0] if args else ""
            if image.startswith("--platform"):
                image = args.split()[1] if len(args.split()) > 1 else ""
            froms.append((lineno, image))
            spec.image = image
            spec.user = ""  # new stage resets the user
            spec.lines.pop("user", None)
        elif instr == "USER":
            spec.user = args
            spec.lines["user"] = lineno
        elif instr == "ENV":
            for key, val in _parse_env(args):
                spec.env[key] = val
                spec.lines[f"env:{key}"] = lineno
        elif instr == "RUN":
            runs.append((lineno, args))
            if re.search(r"--security[= ]insecure", args):
                spec.lines["insecure_build"] = lineno
        elif instr == "VOLUME":
            spec.extra.setdefault("volumes", []).append(args)
        elif instr == "LABEL" and "com.nvidia" in args:
            spec.gpu_requested = True
    spec.extra["runs"] = runs
    spec.extra["froms"] = froms
    if any(re.search(r"nvidia/|cuda", img, re.I) for _, img in froms):
        spec.gpu_requested = True
    if "NVIDIA_VISIBLE_DEVICES" in spec.env:
        spec.gpu_requested = True
    tamper = [(ln, cmd) for ln, cmd in runs if DEV_TAMPER.search(cmd)]
    spec.extra["dev_tamper"] = tamper
    return spec
