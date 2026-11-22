"""Core data models shared by every scanner, prover and generator."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Mount:
    source: str
    target: str
    read_only: bool = False
    type: str = "bind"

    @property
    def is_host_path(self) -> bool:
        return self.type == "bind" and self.source.startswith("/")


@dataclass
class ContainerSpec:
    """A normalized view of how a workload runs, regardless of where it came from.

    Built from `docker inspect`, `docker image inspect`, a Dockerfile, or a
    compose service. Fields that a source cannot express stay at their
    defaults so the analyzer can reason about them uniformly.
    """

    name: str
    source_type: str  # container | image | dockerfile | compose
    source_ref: str
    image: str = ""
    privileged: bool = False
    cap_add: List[str] = field(default_factory=list)
    cap_drop: List[str] = field(default_factory=list)
    mounts: List[Mount] = field(default_factory=list)
    pid_mode: str = ""
    network_mode: str = ""
    ipc_mode: str = ""
    uts_mode: str = ""
    userns_mode: str = ""
    cgroupns_mode: str = ""
    security_opt: List[str] = field(default_factory=list)
    apparmor_profile: str = ""
    devices: List[str] = field(default_factory=list)
    user: str = ""
    env: Dict[str, str] = field(default_factory=dict)
    runtime: str = ""
    gpu_requested: bool = False
    readonly_rootfs: bool = False
    # Source specific extras (Dockerfile instructions, image layer facts, ...)
    extra: Dict[str, Any] = field(default_factory=dict)
    # line numbers for SARIF, keyed by finding hint (e.g. "privileged")
    lines: Dict[str, int] = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    target: str
    detail: str
    cves: List[str] = field(default_factory=list)
    remediation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    file: Optional[str] = None
    line: Optional[int] = None
    # filled by the prover: PROVEN | BLOCKED | NOT_TESTED
    proof: str = "NOT_TESTED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeResult:
    probe_id: str
    title: str
    status: str  # PROVEN | LIKELY | BLOCKED | NA | ERROR
    evidence: str
    rule_ids: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.rule_id, f.target))
