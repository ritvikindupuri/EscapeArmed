import json
import os

import pytest

from escapearmed.analyzer import analyze_spec, nvidia_toolkit_vulnerable, runc_vulnerable
from escapearmed.sources.compose import parse_compose
from escapearmed.sources.dockerfile import parse_dockerfile
from escapearmed.sources.inspect import from_container_inspect

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _read(name):
    with open(os.path.join(FIX, name)) as fh:
        return fh.read()


def ids(findings):
    return {f.rule_id for f in findings}


def test_privileged_inspect():
    spec = from_container_inspect(json.loads(_read("inspect.privileged.json")))
    f = analyze_spec(spec)
    assert {"EA001", "EA002", "EA003", "EA004", "EA006", "EA013"} <= ids(f)
    sock = [x for x in f if x.rule_id == "EA003"][0]
    assert sock.severity == "critical"
    root = [x for x in f if x.rule_id == "EA004"][0]
    assert root.severity == "high"  # read-only host root
    # named volumes under /var/lib/docker are not host bind mounts
    assert not any(x.evidence.get("container_path") == "/cache" for x in f)


def test_compose_services_and_lines():
    specs = parse_compose(_read("compose.vulnerable.yml"), "compose.vulnerable.yml")
    by = {s.name.split("#")[1]: s for s in specs}
    agent = analyze_spec(by["agent"])
    assert {"EA001", "EA003", "EA004", "EA005", "EA006", "EA007"} <= ids(agent)
    priv = [x for x in agent if x.rule_id == "EA001"][0]
    assert priv.line == 4
    gpu = analyze_spec(by["gpu"])
    pre = [x for x in gpu if x.rule_id == "EA017"][0]
    assert pre.severity == "critical" and "CVE-2025-23266" in pre.cves
    web = analyze_spec(by["web"])
    assert {"EA002", "EA009", "EA010"} <= ids(web)
    assert "EA013" not in ids(web)  # runs as uid 101


def test_dockerfile_nvidiascape():
    f = analyze_spec(parse_dockerfile(_read("Dockerfile.nvidiascape"), "Dockerfile.nvidiascape"))
    pre = [x for x in f if x.rule_id == "EA017"][0]
    assert pre.severity == "critical" and pre.line == 3


def test_dockerfile_runc_race_and_insecure():
    f = analyze_spec(parse_dockerfile(_read("Dockerfile.runcrace"), "Dockerfile.runcrace"))
    assert {"EA020", "EA021", "EA013"} <= ids(f)
    race = [x for x in f if x.rule_id == "EA020"][0]
    assert race.line == 3 and "CVE-2025-31133" in race.cves


def test_dockerfile_hardened_is_clean():
    f = analyze_spec(parse_dockerfile(_read("Dockerfile.hardened"), "Dockerfile.hardened"))
    assert ids(f) == set()


@pytest.mark.parametrize("version,expected", [
    ("1.1.15", True), ("1.2.7", True), ("1.2.8", False), ("1.3.0", True), ("1.3.2", True),
    ("1.3.3", False), ("1.3.6+ds1", False), ("1.4.0-rc.2", True), ("1.4.0-rc.3", False),
    ("1.4.0", False), ("garbage", None),
])
def test_runc_version_ranges(version, expected):
    assert runc_vulnerable(version) is expected


def test_nvidia_versions():
    assert nvidia_toolkit_vulnerable("1.17.7") is True
    assert nvidia_toolkit_vulnerable("1.17.8") is False
    assert nvidia_toolkit_vulnerable("1.18.0") is False


def test_host_analysis():
    from escapearmed.analyzer import analyze_host
    facts = {"hostname": "node1", "runc_version": "1.3.1", "nvidia_toolkit_version": "1.17.5",
             "security_options": ["name=seccomp,profile=builtin"],
             "socket": {"path": "/var/run/docker.sock", "mode": 0o666, "group": "docker",
                        "group_members": []}}
    f = {x.rule_id: x for x in analyze_host(facts)}
    assert f["EA015"].severity == "critical" and "CVE-2025-52881" in f["EA015"].cves
    assert f["EA016"].severity == "critical"
    assert f["EA023"].severity == "critical"  # world writable socket
    assert "EA024" in f
    facts.update(runc_version="1.2.8", nvidia_cuda_compat_hook_disabled=True,
                 security_options=["name=userns"])
    facts["socket"]["mode"] = 0o660
    f = {x.rule_id: x for x in analyze_host(facts)}
    assert "EA015" not in f and "EA024" not in f and "EA023" not in f
    assert f["EA016"].severity == "high"
