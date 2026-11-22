"""Generate Kyverno ValidatingPolicy resources (policies.kyverno.io/v1, CEL) that
block the escape primitives that were found.

Kyverno 1.20 removed the legacy kyverno.io ClusterPolicy engine, so the
output uses the CEL based ValidatingPolicy type."""

from __future__ import annotations

from typing import Iterable, List, Set, Tuple

import yaml

from ..catalog import RULES, RUNTIME_SOCKETS
from ..models import Finding

DANGEROUS_CAPS = ["ALL", "SYS_ADMIN", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_PTRACE", "SYS_RAWIO",
                  "BPF", "SYS_BOOT", "PERFMON", "NET_ADMIN"]
HOST_PATH_PREFIXES = ["/proc", "/sys", "/etc", "/dev", "/root", "/boot", "/lib/modules",
                      "/usr/lib/modules", "/var/lib/docker", "/var/lib/containerd",
                      "/var/lib/kubelet", "/var/run", "/run"]


def _cel_list(items: Iterable[str]) -> str:
    return "[" + ", ".join(f"'{i}'" for i in items) + "]"


CAPS_ALL = _cel_list(DANGEROUS_CAPS + [f"CAP_{c}" for c in DANGEROUS_CAPS if c != "ALL"])
VOLUMES = "object.spec.?volumes.orValue([])"
HOST_PATH = "v.?hostPath.?path.orValue('')"

# key -> list of (expression, message)
VALIDATIONS = {
    "privileged": [(
        "variables.allContainers.all(c, !c.?securityContext.?privileged.orValue(false))",
        "EscapeArmed EA001: privileged containers are not allowed.")],
    "capabilities": [(
        f"variables.allContainers.all(c, !c.?securityContext.?capabilities.?add.orValue([])"
        f".exists(cap, cap in {CAPS_ALL}))",
        "EscapeArmed EA002: capabilities that enable container escape (SYS_ADMIN, SYS_MODULE, "
        "DAC_READ_SEARCH, SYS_PTRACE, ...) are not allowed.")],
    "runtime_socket": [(
        f"{VOLUMES}.all(v, !({HOST_PATH} in {_cel_list(RUNTIME_SOCKETS)}))",
        "EscapeArmed EA003: mounting a container runtime socket is not allowed.")],
    "host_path": [(
        f"{VOLUMES}.all(v, {HOST_PATH} != '/' && !{_cel_list(HOST_PATH_PREFIXES)}.exists(p, "
        f"{HOST_PATH} == p || {HOST_PATH}.startsWith(p + '/')))",
        "EscapeArmed EA004/EA005: hostPath mounts of the host root or sensitive host "
        "directories are not allowed.")],
    "host_namespaces": [(
        "!object.spec.?hostPID.orValue(false) && !object.spec.?hostIPC.orValue(false) && "
        "!object.spec.?hostNetwork.orValue(false)",
        "EscapeArmed EA006/EA007/EA008: hostPID, hostIPC and hostNetwork are not allowed.")],
    "apparmor": [(
        "object.spec.?securityContext.?appArmorProfile.?type.orValue('') != 'Unconfined' && "
        "variables.allContainers.all(c, c.?securityContext.?appArmorProfile.?type.orValue('') "
        "!= 'Unconfined') && !object.metadata.?annotations.orValue({}).exists(k, "
        "k.startsWith('container.apparmor.security.beta.kubernetes.io/') && "
        "object.metadata.annotations[k] == 'unconfined')",
        "EscapeArmed EA009: AppArmor must not be Unconfined.")],
    "seccomp": [(
        "object.spec.?securityContext.?seccompProfile.?type.orValue('') != 'Unconfined' && "
        "variables.allContainers.all(c, c.?securityContext.?seccompProfile.?type.orValue('') "
        "!= 'Unconfined')",
        "EscapeArmed EA010: seccomp must not be Unconfined.")],
    "privilege_escalation": [(
        "variables.allContainers.all(c, c.?securityContext.?allowPrivilegeEscalation.orValue(true) == false)",
        "EscapeArmed EA014: set allowPrivilegeEscalation: false on every container.")],
    "ld_preload": [(
        "variables.allContainers.all(c, !c.?env.orValue([]).exists(e, e.name == 'LD_PRELOAD'))",
        "EscapeArmed EA017: LD_PRELOAD in a container env is the NVIDIAScape (CVE-2025-23266) "
        "trigger and is not allowed.")],
}

AUDIT_VALIDATIONS = {
    "run_as_non_root": [
        ("object.spec.?securityContext.?runAsNonRoot.orValue(false) || "
         "variables.allContainers.all(c, c.?securityContext.?runAsNonRoot.orValue(false))",
         "EscapeArmed EA013: containers should set runAsNonRoot: true."),
        ("object.spec.?hostUsers.orValue(true) == false",
         "EscapeArmed EA013: run pods in a user namespace (hostUsers: false). This neutralizes "
         "CVE-2025-31133, CVE-2025-52565 and CVE-2025-52881."),
    ],
}

ALL_KEYS = set(VALIDATIONS) | set(AUDIT_VALIDATIONS)
# Kyverno stops at the first failing validation, so the most severe come first.
ORDER = ["privileged", "runtime_socket", "host_path", "host_namespaces", "capabilities",
         "ld_preload", "apparmor", "seccomp", "privilege_escalation"]

# privileged implies the sub controls are also worth enforcing
IMPLIES = {"privileged": {"capabilities", "apparmor", "seccomp"}}


def keys_from_findings(findings: Iterable[Finding]) -> Set[str]:
    keys: Set[str] = set()
    for f in findings:
        rule = RULES.get(f.rule_id)
        if rule and rule.kyverno:
            keys.add(rule.kyverno)
    for k in list(keys):
        keys |= IMPLIES.get(k, set())
    return keys


def _policy(name: str, actions: List[str], validations: List[Tuple[str, str]], title: str) -> dict:
    return {
        "apiVersion": "policies.kyverno.io/v1",
        "kind": "ValidatingPolicy",
        "metadata": {
            "name": name,
            "annotations": {
                "policies.kyverno.io/title": title,
                "policies.kyverno.io/category": "Container Escape",
                "policies.kyverno.io/severity": "high",
                "policies.kyverno.io/subject": "Pod",
                "policies.kyverno.io/description": (
                    "Generated by EscapeArmed from scan findings. Blocks the configuration "
                    "primitives used for container escape, including the setups that make "
                    "CVE-2025-31133, CVE-2025-52565, CVE-2025-52881 and CVE-2025-23266 exploitable."),
            },
        },
        "spec": {
            "validationActions": actions,
            "evaluation": {"background": {"enabled": True}},
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                "resources": ["pods"]}]},
            "variables": [{
                "name": "allContainers",
                "expression": "object.spec.containers + object.spec.?initContainers.orValue([]) "
                              "+ object.spec.?ephemeralContainers.orValue([])"}],
            "validations": [{"expression": e, "message": m} for e, m in validations],
        },
    }


def generate(findings: Iterable[Finding], action: str = "Enforce", all_rules: bool = False,
             name: str = "escapearmed-block-escape-primitives") -> str:
    keys = ALL_KEYS if all_rules else keys_from_findings(findings)
    deny = [v for k in ORDER if k in keys for v in VALIDATIONS[k]]
    audit = [v for k in sorted(AUDIT_VALIDATIONS) if k in keys for v in AUDIT_VALIDATIONS[k]]
    docs = []
    if deny:
        docs.append(_policy(name, ["Deny"] if action == "Enforce" else ["Audit"], deny,
                            "Block container escape primitives (EscapeArmed)"))
    if audit:
        docs.append(_policy(name + "-audit", ["Audit"], audit,
                            "Audit root and missing user namespaces (EscapeArmed)"))
    header = ("# Generated by EscapeArmed. Kyverno ValidatingPolicy (policies.kyverno.io/v1, CEL),\n"
              "# for Kyverno 1.17 and later.\n")
    if not docs:
        return header + "# No policy needed: no admission-relevant findings.\n"
    return header + yaml.safe_dump_all(docs, sort_keys=False, width=110)
