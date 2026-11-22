"""Human readable and JSON reports."""

from __future__ import annotations

import json
import sys
from collections import Counter
from typing import Dict, List, Optional

from . import __version__
from .catalog import CVE_INFO
from .models import Finding, sort_findings

COLORS = {"critical": "\033[1;91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[96m",
          "info": "\033[37m", "PROVEN": "\033[1;91m", "LIKELY": "\033[93m", "BLOCKED": "\033[92m",
          "NA": "\033[37m", "ERROR": "\033[95m", "bold": "\033[1m", "reset": "\033[0m"}


def _c(key: str, text: str, color: bool) -> str:
    return f"{COLORS.get(key, '')}{text}{COLORS['reset']}" if color else text


def render_text(findings: List[Finding], *, targets: List[str], host: Optional[Dict] = None,
                proof: Optional[Dict] = None, color: Optional[bool] = None) -> str:
    if color is None:
        color = sys.stdout.isatty()
    findings = sort_findings(findings)
    lines: List[str] = []
    w = lines.append
    w(_c("bold", f"EscapeArmed {__version__}  container escape readiness report", color))
    w("")
    w(_c("bold", "Targets", color))
    for t in targets:
        w(f"  - {t}")
    if host:
        w("")
        w(_c("bold", "Host", color))
        w(f"  - engine {host.get('engine_version', '?')}, runc {host.get('runc_version', '?')}, "
          f"cgroup v{host.get('cgroup_version', '?')}, kernel {host.get('kernel', '?')}")
        if host.get("nvidia_toolkit_version"):
            w(f"  - NVIDIA Container Toolkit {host['nvidia_toolkit_version']}")
        w(f"  - security options: {', '.join(host.get('security_options', [])) or 'none'}")
    counts = Counter(f.severity for f in findings)
    w("")
    w(_c("bold", "Summary", color))
    w("  " + "  ".join(_c(s, f"{s.upper()} {counts.get(s, 0)}", color)
                       for s in ("critical", "high", "medium", "low", "info")))
    if proof:
        w("  Verdict: " + _c("PROVEN" if proof["verdict"] == "ESCAPABLE" else "LIKELY"
                             if proof["verdict"] == "AT RISK" else "BLOCKED", proof["verdict"], color))
    w("")
    w(_c("bold", "Findings", color))
    if not findings:
        w("  No escape primitives found.")
    for f in findings:
        loc = f"  ({f.file}:{f.line})" if f.file and f.line else ""
        tag = f" [{f.proof}]" if f.proof not in ("NOT_TESTED", "") else ""
        w(f"  {_c(f.severity, f.severity.upper().ljust(8), color)} {f.rule_id} {f.title}{tag}{loc}")
        w(f"           {f.target}: {f.detail}")
        if f.cves:
            w(f"           CVEs: {', '.join(f.cves)}")
        w(f"           Fix: {f.remediation}")
    if proof:
        w("")
        w(_c("bold", "Active proof (canary probes)", color))
        for r in proof["results"]:
            w(f"  {_c(r['status'], r['status'].ljust(8), color)} {r['title']}")
            w(f"           {r['evidence']}")
        if proof.get("info"):
            for k, v in proof["info"].items():
                if k != "done":
                    w(f"  INFO     {k}: {v}")
        left = proof.get("canaries_left") or []
        w(f"  Cleanup: {len(proof.get('canaries_cleaned', []))} canary file(s) removed"
          + (f", {len(left)} left: {', '.join(left)}" if left else ", nothing left behind"))
    cves = sorted({c for f in findings for c in f.cves})
    if cves:
        w("")
        w(_c("bold", "CVE context", color))
        for c in cves:
            info = CVE_INFO.get(c)
            if info:
                w(f"  - {c} {info['name']}. Fixed in {info['fixed_in']}.")
    return "\n".join(lines) + "\n"


def render_json(findings: List[Finding], *, targets: List[str], host: Optional[Dict] = None,
                proof: Optional[Dict] = None) -> str:
    findings = sort_findings(findings)
    counts = Counter(f.severity for f in findings)
    doc = {
        "tool": "EscapeArmed",
        "version": __version__,
        "targets": targets,
        "host": host,
        "summary": {s: counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        "findings": [f.to_dict() for f in findings],
        "proof": proof,
    }
    return json.dumps(doc, indent=2, default=str)


def findings_from_json(text: str) -> List[Finding]:
    doc = json.loads(text)
    return [Finding(**f) for f in doc.get("findings", [])]
