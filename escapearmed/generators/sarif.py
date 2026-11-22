"""SARIF 2.1.0 output for GitHub code scanning and other CI tools."""

from __future__ import annotations

import json
from typing import Dict, List

from .. import __version__
from ..catalog import CVE_INFO, RULES
from ..models import Finding

SEC_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _rule_descriptor(rule_id: str) -> Dict:
    rule = RULES[rule_id]
    help_lines = [rule.description, "", f"Fix: {rule.remediation}"]
    for cve in rule.cves:
        info = CVE_INFO.get(cve)
        if info:
            help_lines.append(f"{cve}: {info['name']}. Fixed in {info['fixed_in']}. {info['url']}")
    return {
        "id": rule.id,
        "name": rule.title.replace(" ", ""),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {"text": "\n".join(help_lines)},
        "defaultConfiguration": {"level": LEVEL[rule.severity]},
        "properties": {
            "security-severity": SEC_SEVERITY[rule.severity],
            "tags": ["security", "container", "container-escape"] + rule.cves,
        },
    }


def generate(findings: List[Finding]) -> str:
    used = sorted({f.rule_id for f in findings})
    index = {rid: i for i, rid in enumerate(used)}
    results = []
    for f in findings:
        uri = f.file or f"container/{f.target}".replace(":", "_")
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {f.detail}" + (
                f" Related: {', '.join(f.cves)}." if f.cves else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": max(1, int(f.line or 1))},
            }}],
            "properties": {"security-severity": SEC_SEVERITY.get(f.severity, "5.5"),
                           "target": f.target, "proof": f.proof},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "EscapeArmed",
                "version": __version__,
                "informationUri": "https://github.com/ritvikindupuri/EscapeArmed",
                "rules": [_rule_descriptor(rid) for rid in used],
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
