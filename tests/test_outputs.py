import json
import os

import yaml

from escapearmed.analyzer import analyze_spec
from escapearmed.generators import falco, kyverno, sarif
from escapearmed.prover import interpret, parse_probe_output, verdict
from escapearmed.report import findings_from_json, render_json, render_text
from escapearmed.sources.compose import parse_compose

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _findings():
    with open(os.path.join(FIX, "compose.vulnerable.yml")) as fh:
        specs = parse_compose(fh.read(), "compose.vulnerable.yml")
    out = []
    for s in specs:
        out.extend(analyze_spec(s))
    return out


def test_sarif_shape():
    doc = json.loads(sarif.generate(_findings()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    for res in run["results"]:
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        assert res["level"] in ("error", "warning", "note")


def test_kyverno_policy_only_detected_rules():
    docs = list(yaml.safe_load_all(kyverno.generate(_findings())))
    deny = docs[0]
    assert deny["kind"] == "ValidatingPolicy" and deny["apiVersion"] == "policies.kyverno.io/v1"
    assert deny["spec"]["validationActions"] == ["Deny"]
    msgs = " ".join(v["message"] for v in deny["spec"]["validations"])
    for rid in ("EA001", "EA003", "EA017", "EA006"):
        assert rid in msgs
    assert docs[1]["spec"]["validationActions"] == ["Audit"]


def test_kyverno_clean_input_has_no_policy():
    assert "No policy needed" in kyverno.generate([])


def test_falco_rules_self_contained():
    doc = yaml.safe_load(falco.generate(_findings()))
    macros = {d["macro"] for d in doc if "macro" in d}
    rules = [d for d in doc if "rule" in d]
    assert rules
    for r in rules:
        if "NVIDIAScape" not in r["rule"]:  # the NVIDIA hook runs on the host, not in a container
            assert "ea_container" in r["condition"]
        for token in r["condition"].replace("(", " ").replace(")", " ").split():
            if token.startswith("ea_"):
                assert token in macros
    assert any("NVIDIAScape" in r["rule"] for r in rules)


def test_json_roundtrip_and_text():
    f = _findings()
    js = render_json(f, targets=["compose"])
    back = findings_from_json(js)
    assert len(back) == len(f)
    txt = render_text(f, targets=["compose"], color=False)
    assert "EA001" in txt and "\u2014" not in txt


def test_probe_interpretation(tmp_path):
    from escapearmed.models import ContainerSpec, Mount
    token = "abc123"
    (tmp_path / f".escapearmed-canary-{token}").write_text(f"escapearmed canary {token}\n")
    spec = ContainerSpec(name="t", source_type="container", source_ref="t",
                         mounts=[Mount(source=str(tmp_path), target="/data")])
    out = "\n".join([
        "EA|identity|INFO|uid=0",
        f"EA|host_write|WROTE|/data|/data/.escapearmed-canary-{token}",
        "EA|runtime_socket|PROVEN|GET /version answered",
        "EA|core_pattern|BLOCKED|read-only",
        "noise line",
    ])
    results, cleanup, info = interpret(parse_probe_output(out), spec, token)
    st = {r.probe_id: r.status for r in results}
    assert st == {"host_write": "PROVEN", "runtime_socket": "PROVEN", "core_pattern": "BLOCKED"}
    assert cleanup == [f"/data/.escapearmed-canary-{token}"]
    assert info["identity"] == "uid=0"
    assert verdict(results) == "ESCAPABLE"
