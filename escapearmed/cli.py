"""escapearmed command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Tuple

from . import __version__
from .analyzer import analyze_host, analyze_spec
from .catalog import CVE_INFO, RULES
from .docker import Docker, DockerError
from .generators import falco, kyverno, sarif
from .models import SEVERITY_ORDER, ContainerSpec, Finding
from .report import findings_from_json, render_json, render_text
from .sources.compose import parse_compose
from .sources.dockerfile import parse_dockerfile
from .sources.inspect import from_container_inspect, from_image_inspect

BANNER_ACTIVE = """\
!! EscapeArmed ACTIVE MODE !!
You are about to run canary probes inside container: {name}
  - probes run as {user} inside the container with `docker exec`
  - they only read, test write access, mount and unmount scratch filesystems,
    and write one canary file per writable host bind mount, removed afterwards
  - nothing is written to core_pattern, sysrq-trigger, release_agent or modules
  - only run this against containers you own and have permission to test
"""


def _write(path: Optional[str], content: str) -> None:
    if not path or path == "-":
        sys.stdout.write(content)
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def _collect(args, docker: Docker) -> Tuple[List[Finding], List[str], Optional[dict], List[ContainerSpec]]:
    findings: List[Finding] = []
    targets: List[str] = []
    specs: List[ContainerSpec] = []
    host = None
    kind = args.kind
    if kind == "container":
        for ref in args.targets:
            spec = from_container_inspect(docker.inspect_container(ref))
            specs.append(spec)
            targets.append(f"container {spec.name} (image {spec.image})")
    elif kind == "image":
        for ref in args.targets:
            spec = from_image_inspect(docker.inspect_image(ref), ref)
            if not args.no_layers:
                from .sources.layers import scan_image_layers
                spec.extra["layer_hits"] = scan_image_layers(docker, ref)
            specs.append(spec)
            targets.append(f"image {ref}")
    elif kind == "dockerfile":
        for path in args.targets:
            with open(path) as fh:
                specs.append(parse_dockerfile(fh.read(), path))
            targets.append(f"dockerfile {path}")
    elif kind == "compose":
        for path in args.targets:
            with open(path) as fh:
                specs.extend(parse_compose(fh.read(), path))
            targets.append(f"compose {path}")
    elif kind == "all-containers":
        ids = docker.run(["ps", "-q"]).stdout.decode().split()
        for cid in ids:
            spec = from_container_inspect(docker.inspect_container(cid))
            specs.append(spec)
            targets.append(f"container {spec.name} (image {spec.image})")
    for spec in specs:
        findings.extend(analyze_spec(spec))
    if kind in ("host", "container", "all-containers") or getattr(args, "with_host", False):
        from .hostfacts import collect
        host = collect(docker)
        findings.extend(analyze_host(host))
        if kind == "host":
            targets.append(f"host {host.get('hostname')}")
    return findings, targets, host, specs


def _emit(args, findings, targets, host, proof=None) -> None:
    fmt = args.format
    if fmt == "json":
        _write(args.output, render_json(findings, targets=targets, host=host, proof=proof))
    elif fmt == "sarif":
        _write(args.output, sarif.generate(findings))
    else:
        _write(args.output, render_text(findings, targets=targets, host=host, proof=proof,
                                        color=False if args.no_color or args.output else None))
    if args.emit_dir:
        d = args.emit_dir
        os.makedirs(d, exist_ok=True)
        _write(os.path.join(d, "report.txt"),
               render_text(findings, targets=targets, host=host, proof=proof, color=False))
        _write(os.path.join(d, "report.json"),
               render_json(findings, targets=targets, host=host, proof=proof))
        _write(os.path.join(d, "escapearmed.sarif"), sarif.generate(findings))
        _write(os.path.join(d, "kyverno-policy.yaml"), kyverno.generate(findings))
        _write(os.path.join(d, "falco-rules.yaml"), falco.generate(findings))
        sys.stderr.write(f"[escapearmed] wrote report.txt, report.json, escapearmed.sarif, "
                         f"kyverno-policy.yaml, falco-rules.yaml to {d}\n")


def _exit_code(findings: List[Finding], fail_on: Optional[str]) -> int:
    if not fail_on:
        return 0
    floor = SEVERITY_ORDER[fail_on]
    return 2 if any(SEVERITY_ORDER.get(f.severity, 0) >= floor for f in findings) else 0


def cmd_scan(args) -> int:
    docker = Docker(args.docker)
    findings, targets, host, _ = _collect(args, docker)
    _emit(args, findings, targets, host)
    return _exit_code(findings, args.fail_on)


def _apply_proof(findings: List[Finding], proof: dict) -> None:
    by_rule = {}
    for r in proof["results"]:
        for rid in r["rule_ids"]:
            by_rule.setdefault(rid, []).append(r["status"])
    for f in findings:
        statuses = by_rule.get(f.rule_id, [])
        if "PROVEN" in statuses:
            f.proof = "PROVEN"
            if SEVERITY_ORDER.get(f.severity, 0) < SEVERITY_ORDER["high"]:
                f.severity = "high"  # a proven escape step is never just medium
        elif "LIKELY" in statuses:
            f.proof = "LIKELY"
        elif statuses and all(s in ("BLOCKED", "NA") for s in statuses):
            f.proof = "BLOCKED"


def cmd_prove(args) -> int:
    if not (args.active and args.i_understand):
        sys.stderr.write("prove runs canary probes inside a live container. Re-run with both "
                         "--active and --i-understand to confirm you own the target.\n")
        return 64
    from .prover import run_proof
    docker = Docker(args.docker)
    data = docker.inspect_container(args.container)
    spec = from_container_inspect(data)
    if spec.extra.get("state") != "running":
        sys.stderr.write(f"container {spec.name} is not running\n")
        return 65
    user = "root (forced with --as-root)" if args.as_root else f"the container user ({spec.user or 'root'})"
    sys.stderr.write(BANNER_ACTIVE.format(name=spec.name, user=user))
    if not args.yes:
        if not sys.stdin.isatty():
            sys.stderr.write("refusing to run without a TTY confirmation, pass --yes for automation\n")
            return 64
        answer = input(f"Type the container name ({spec.name}) to continue: ").strip()
        if answer != spec.name:
            sys.stderr.write("aborted\n")
            return 1
    findings = analyze_spec(spec)
    from .hostfacts import collect
    host = collect(docker)
    findings.extend(analyze_host(host))
    proof = run_proof(docker, args.container, spec, as_root=args.as_root,
                      local_host=not args.remote_daemon)
    _apply_proof(findings, proof)
    _emit(args, findings, [f"container {spec.name} (image {spec.image})"], host, proof)
    if args.fail_on_escape and proof["verdict"] == "ESCAPABLE":
        return 3
    return _exit_code(findings, args.fail_on)


def cmd_gen_policy(args) -> int:
    findings: List[Finding] = []
    if args.from_report:
        with open(args.from_report) as fh:
            findings = findings_from_json(fh.read())
    elif not args.all:
        sys.stderr.write("pass --from report.json (from `scan -f json`) or --all\n")
        return 64
    if args.kind in ("kyverno", "both"):
        _write(args.kyverno_out, kyverno.generate(findings, action=args.action, all_rules=args.all))
    if args.kind in ("falco", "both"):
        _write(args.falco_out, falco.generate(findings, all_rules=args.all))
    return 0


def cmd_rules(args) -> int:
    for rule in RULES.values():
        cves = f"  [{', '.join(rule.cves)}]" if rule.cves else ""
        print(f"{rule.id}  {rule.severity.upper():8} {rule.title}{cves}")
    print()
    for cve, info in CVE_INFO.items():
        print(f"{cve}  {info['name']}  (fixed in {info['fixed_in']})")
    return 0


def _add_output(p: argparse.ArgumentParser) -> None:
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", help="write the main output to a file")
    p.add_argument("--emit-dir", help="also write report, json, sarif, kyverno and falco files here")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 2 if any finding >= severity")
    p.add_argument("--no-color", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="escapearmed",
                                 description="Container escape readiness scanner and prover.")
    ap.add_argument("--version", action="version", version=f"escapearmed {__version__}")
    ap.add_argument("--docker", default=os.environ.get("ESCAPEARMED_DOCKER", "docker"),
                    help="docker command to use, e.g. 'sudo docker' (env ESCAPEARMED_DOCKER)")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="static scan for escape primitives")
    s.add_argument("kind", choices=["container", "image", "dockerfile", "compose", "host",
                                    "all-containers"])
    s.add_argument("targets", nargs="*")
    s.add_argument("--no-layers", action="store_true", help="image: skip the layer symlink scan")
    s.add_argument("--with-host", action="store_true", help="include host checks for file scans")
    _add_output(s)
    s.set_defaults(func=cmd_scan)

    p = sub.add_parser("prove", help="ACTIVE: run harmless canary escape probes in a container")
    p.add_argument("container")
    p.add_argument("--active", action="store_true", help="required, enables active probes")
    p.add_argument("--i-understand", action="store_true", help="required, you own the target")
    p.add_argument("--yes", action="store_true", help="skip the interactive confirmation")
    p.add_argument("--as-root", action="store_true", help="probe as UID 0 inside the container")
    p.add_argument("--remote-daemon", action="store_true",
                   help="daemon is remote, skip host side canary verification")
    p.add_argument("--fail-on-escape", action="store_true", help="exit 3 if an escape is proven")
    _add_output(p)
    p.set_defaults(func=cmd_prove)

    g = sub.add_parser("gen-policy", help="generate Kyverno and Falco artifacts")
    g.add_argument("kind", choices=["kyverno", "falco", "both"], nargs="?", default="both")
    g.add_argument("--from", dest="from_report", help="report.json from scan or prove")
    g.add_argument("--all", action="store_true", help="emit every rule, not only detected ones")
    g.add_argument("--action", choices=["Enforce", "Audit"], default="Enforce")
    g.add_argument("--kyverno-out", default="-")
    g.add_argument("--falco-out", default="-")
    g.set_defaults(func=cmd_gen_policy)

    r = sub.add_parser("rules", help="list detection rules and CVEs")
    r.set_defaults(func=cmd_rules)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan" and args.kind not in ("host", "all-containers") and not args.targets:
        sys.stderr.write(f"scan {args.kind} needs at least one target\n")
        return 64
    try:
        return args.func(args)
    except DockerError as exc:
        sys.stderr.write(f"[escapearmed] docker error: {exc}\n")
        return 70
    except FileNotFoundError as exc:
        sys.stderr.write(f"[escapearmed] {exc}\n")
        return 66


if __name__ == "__main__":
    sys.exit(main())
