"""abs rule tests: the malicious fixture must fire, the clean one must not."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from abs_scan.cli import scan, sarif  # noqa: E402
from abs_scan.rules import _is_overbroad_allow  # noqa: E402

CORPUS = Path(__file__).resolve().parents[1] / "corpus"


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    out = {}
    for kind in ("malicious", "clean"):
        dest = tmp_path_factory.mktemp(f"abs-{kind}")
        subprocess.run([sys.executable, str(CORPUS / "gen.py"), str(dest), kind],
                       check=True, capture_output=True)
        out[kind] = dest
    return out


def ids(root):
    return {f["id"] for f in scan(root)}


EXPECTED = {
    "GIT-001", "GIT-002", "GIT-003", "GIT-004", "GIT-008",   # repo git config sinks
    "GIT-010", "GIT-011",                                     # filter drivers
    "GIT-013",                                                # path-confusing worktree
    "CC-001", "CC-002", "CC-003",                             # claude code settings
    "CTX-001",                                                # instruction injection
    "MCP-001", "MCP-002",                                     # repo-declared MCP
    "FS-001",                                                 # symlink escape
    "ENV-001",                                                # git env channel in .env
    "DEV-001", "DEV-002",                                     # devcontainer lifecycle + extensions
    "VS-001",                                                 # vscode task on folder open
    "HK-001",                                                 # git hook shipped in the repo
    "EN-001",                                                 # direnv .envrc
    "PKG-001",                                                # npm lifecycle script
}


def test_malicious_fixture_fires_every_family(fixtures):
    found = ids(fixtures["malicious"])
    missing = EXPECTED - found
    assert not missing, f"rules did not fire on the malicious fixture: {sorted(missing)}"


def test_clean_fixture_is_quiet(fixtures):
    assert scan(fixtures["clean"]) == [], "clean fixture must produce no findings"


def test_sarif_is_well_formed(fixtures):
    doc = sarif(fixtures["malicious"], scan(fixtures["malicious"]))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "agent-boundary-scan"
    assert len(run["results"]) == len(scan(fixtures["malicious"]))
    for result in run["results"]:
        assert result["ruleId"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_fail_on_exit_code(fixtures):
    here = Path(__file__).resolve().parents[1]
    for kind, expected in (("malicious", 1), ("clean", 0)):
        proc = subprocess.run([sys.executable, "-m", "abs_scan", str(fixtures[kind]),
                               "--fail-on", "high"], cwd=here, capture_output=True)
        assert proc.returncode == expected, f"{kind}: exit {proc.returncode}"


def test_json_format_is_parseable(fixtures):
    here = Path(__file__).resolve().parents[1]
    proc = subprocess.run([sys.executable, "-m", "abs_scan", str(fixtures["malicious"]),
                           "--format", "json"], cwd=here, capture_output=True, text=True)
    payload = json.loads(proc.stdout)
    assert {f["severity"] for f in payload} <= {"critical", "high", "medium", "low", "info"}
    for f in payload:
        assert {"id", "title", "severity", "path", "fix"} <= set(f)


@pytest.mark.parametrize("rule,expected", [
    ("Bash(git status)", False),
    ("Bash(git *)", True),
    ("Bash(*)", True),
    ("Write(/**/*)", True),
    ("Read(src/**)", True),
    ("mcp__github__*", True),
    ("WebFetch(domain:example.com)", False),
])
def test_overbroad_allow(rule, expected):
    assert _is_overbroad_allow(rule) is expected


def test_section_normalisation():
    from abs_scan.rules import _normalise_section
    assert _normalise_section('protocol "ext"') == "protocol.ext"
    assert _normalise_section("core") == "core"
    assert _normalise_section('filter "p"') == "filter.p"
