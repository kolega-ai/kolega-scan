"""Unit + end-to-end tests for the Kolega Scan OSS scanner pipeline (v1/v2/ref)."""

from __future__ import annotations

import json

import pytest

from kolega_security_scanner.llm.fake import FakeLLMClient
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.enumerate import enumerate_sources
from kolega_security_scanner.scanners.claude_adaptation.config import PipelineConfig
from kolega_security_scanner.scanners.claude_adaptation.discovery import discover_partition
from kolega_security_scanner.scanners.claude_adaptation.findings import to_finding
from kolega_security_scanner.scanners.claude_adaptation.models import (
    Candidate,
    Partition,
    ThreatModel,
    Verdict,
    VerifiedCandidate,
)
from kolega_security_scanner.scanners.claude_adaptation.partition import (
    partition_files,
    select_entry_points,
)
from kolega_security_scanner.scanners.claude_adaptation.provider import (
    ClaudeAdaptationScanProvider,
)
from kolega_security_scanner.scanners.claude_adaptation.threat_model import build_threat_model
from kolega_security_scanner.scanners.claude_adaptation.triage import deduplicate, triage
from kolega_security_scanner.scanners.claude_adaptation.verification import verify_candidate

_VULN_PY = """\
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    db = sqlite3.connect("app.db")
    # SQL injection: untrusted id concatenated into the query.
    return db.execute("SELECT * FROM users WHERE id = " + uid).fetchall()
"""


@pytest.fixture
def repo(tmp_path):
    """A tiny single-file Flask repo with an obvious SQL injection."""
    (tmp_path / "app.py").write_text(_VULN_PY)
    return tmp_path


def _tm_json() -> str:
    return json.dumps(
        {
            "summary": "Flask web app exposing a user endpoint.",
            "assets": ["user records"],
            "entry_points": ["/user"],
            "trust_boundaries": ["anon -> db"],
            "trusted_inputs": [],
            "vuln_classes": ["sql_injection"],
        }
    )


def _discovery_json() -> str:
    return json.dumps(
        {
            "findings": [
                {
                    "rationale": "request.args id concatenated into SQL",
                    "title": "SQL injection in get_user",
                    "vuln_class": "sql_injection",
                    "file": "app.py",
                    "line": 12,
                    "impact": "read arbitrary rows",
                    "cwe": "CWE-89",
                    "severity": "high",
                    "confidence": "high",
                }
            ]
        }
    )


def _verify_json(exploitable: bool) -> str:
    return json.dumps(
        {
            "reason": "id reaches execute() unsanitized",
            "severity": "critical",
            "exploitable": exploitable,
        }
    )


# --- Phase 1: threat model -------------------------------------------------


def test_threat_model_parses(repo):
    target = enumerate_sources(repo)
    llm = FakeLLMClient([_tm_json()])
    tm = build_threat_model(target, llm, PipelineConfig())
    assert tm.status == "ok"
    assert "sql_injection" in tm.vuln_classes


def test_threat_model_degrades_on_bad_json(repo):
    target = enumerate_sources(repo)
    tm = build_threat_model(target, FakeLLMClient(["not json"]), PipelineConfig())
    assert tm.status == "error:no_json"


# --- Phase 3a: partition ---------------------------------------------------


def test_partition_groups_by_component(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("y = 2\n")
    target = enumerate_sources(tmp_path)
    parts = partition_files(target, max_files=10)
    names = {p.name for p in parts}
    assert "<root>" in names and "pkg" in names


def test_partition_splits_oversized(tmp_path):
    (tmp_path / "pkg").mkdir()
    for i in range(5):
        (tmp_path / "pkg" / f"f{i}.py").write_text("x = 1\n")
    target = enumerate_sources(tmp_path)
    parts = partition_files(target, max_files=2)
    pkg_parts = [p for p in parts if p.name.startswith("pkg")]
    assert len(pkg_parts) == 3  # 5 files / 2 per chunk -> 3 chunks


def test_select_entry_points_prefers_hints(repo):
    target = enumerate_sources(repo)
    chosen = select_entry_points(target, max_files=5)
    assert "app.py" in chosen


# --- Phase 3: discovery ----------------------------------------------------


def test_discovery_parses_and_validates_path(repo):
    target = enumerate_sources(repo)
    part = Partition(name="<root>", files=("app.py",))
    llm = FakeLLMClient([_discovery_json()])
    cands = discover_partition(target, part, ThreatModel(), llm, PipelineConfig())
    assert len(cands) == 1
    assert cands[0].vuln_class == "sql_injection"
    assert cands[0].path == "app.py"


def test_discovery_drops_hallucinated_path(repo):
    target = enumerate_sources(repo)
    part = Partition(name="<root>", files=("app.py",))
    bad = json.dumps({"findings": [{"file": "nope.py", "line": 1, "vuln_class": "x"}]})
    cands = discover_partition(target, part, ThreatModel(), FakeLLMClient([bad]), PipelineConfig())
    assert cands == []


def test_discovery_clamps_line(repo):
    target = enumerate_sources(repo)
    part = Partition(name="<root>", files=("app.py",))
    huge = json.dumps(
        {"findings": [{"file": "app.py", "line": 9999, "vuln_class": "x", "cwe": "CWE-1"}]}
    )
    cands = discover_partition(target, part, ThreatModel(), FakeLLMClient([huge]), PipelineConfig())
    assert cands[0].line <= len(_VULN_PY.splitlines())


# --- Phase 4: verification -------------------------------------------------


def _candidate() -> Candidate:
    return Candidate(
        path="app.py",
        line=12,
        title="SQLi",
        vuln_class="sql_injection",
        cwe="CWE-89",
        rationale="r",
        impact="i",
        severity="high",
        confidence="high",
    )


def test_verify_confirms(repo):
    target = enumerate_sources(repo)
    llm = FakeLLMClient([_verify_json(True)])
    vc = verify_candidate(target, _candidate(), ThreatModel(), llm, PipelineConfig())
    assert vc.verdict.exploitable is True
    assert vc.verdict.severity == "critical"


def test_verify_rejects(repo):
    target = enumerate_sources(repo)
    llm = FakeLLMClient([_verify_json(False)])
    vc = verify_candidate(target, _candidate(), ThreatModel(), llm, PipelineConfig())
    assert vc.verdict.exploitable is False


def test_verify_majority_vote(repo):
    target = enumerate_sources(repo)
    # 2 yes, 1 no -> strict majority confirms.
    llm = FakeLLMClient([_verify_json(True), _verify_json(True), _verify_json(False)])
    cfg = PipelineConfig(verifiers=3)
    vc = verify_candidate(target, _candidate(), ThreatModel(), llm, cfg)
    assert vc.verdict.exploitable is True
    assert len(vc.votes) == 3


# --- Phase 5: triage -------------------------------------------------------


def _vc(line: int, sev: str, cls: str = "sql_injection") -> VerifiedCandidate:
    c = Candidate(
        path="app.py",
        line=line,
        title="t",
        vuln_class=cls,
        cwe="CWE-89",
        rationale="r",
        impact="i",
        severity=sev,
        confidence="high",
    )
    return VerifiedCandidate(candidate=c, verdict=Verdict(exploitable=True))


def test_dedupe_collapses_nearby_same_class():
    kept = deduplicate([_vc(10, "high"), _vc(15, "low")])
    assert len(kept) == 1
    assert kept[0].candidate.severity == "high"  # highest severity representative


def test_dedupe_keeps_distant_and_distinct():
    kept = deduplicate([_vc(10, "high"), _vc(40, "high"), _vc(10, "high", cls="ssrf")])
    assert len(kept) == 3


def test_triage_ranks_by_severity():
    ranked = triage([_vc(40, "low"), _vc(10, "critical", cls="ssrf")])
    assert ranked[0].candidate.severity == "critical"


# --- findings conversion ---------------------------------------------------


def test_to_finding_sanitizes_cwe():
    c = Candidate(
        path="app.py",
        line=1,
        title="t",
        vuln_class="weird class!",
        cwe="garbage",
        rationale="r",
        impact="i",
        severity="high",
        confidence="medium",
    )
    f = to_finding(VerifiedCandidate(candidate=c, verdict=Verdict(exploitable=True)))
    assert f.extra.metadata.cwe == ["CWE-693"]  # fallback
    assert f.check_id == "kolega.claude-adaptation.weird-class"


def test_to_finding_verifier_severity_wins():
    c = _candidate()
    vc = VerifiedCandidate(candidate=c, verdict=Verdict(exploitable=True, severity="critical"))
    assert to_finding(vc).extra.severity == "critical"


# --- end-to-end provider ---------------------------------------------------


def _inject_llm(monkeypatch, llm):
    """The provider builds its own client from env; inject a fake at that seam."""
    import kolega_security_scanner.llm.client as _m

    monkeypatch.setattr(_m, "build_llm_client", lambda env_var="LITELLM_API_KEY": llm)


def test_provider_end_to_end(repo, monkeypatch):
    # Call order: threat-model, discovery (1 partition), verify (1 candidate).
    _inject_llm(monkeypatch, FakeLLMClient([_tm_json(), _discovery_json(), _verify_json(True)]))
    cfg = ScanConfig(repo_path=repo)
    result = ClaudeAdaptationScanProvider().scan(cfg)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.path == "app.py"
    assert f.extra.metadata.cwe == ["CWE-89"]
    assert f.extra.severity == "critical"  # verifier recalibrated


def test_provider_drops_unverified(repo, monkeypatch):
    _inject_llm(monkeypatch, FakeLLMClient([_tm_json(), _discovery_json(), _verify_json(False)]))
    cfg = ScanConfig(repo_path=repo)
    result = ClaudeAdaptationScanProvider().scan(cfg)
    assert result.findings == []


def test_provider_no_sources(tmp_path, monkeypatch):
    _inject_llm(monkeypatch, FakeLLMClient([]))
    cfg = ScanConfig(repo_path=tmp_path)
    result = ClaudeAdaptationScanProvider().scan(cfg)
    assert result.findings == []


def test_provider_missing_key_raises(no_llm_env, repo):
    import pytest

    from kolega_security_scanner.cli._errors import LLMConfigError

    with pytest.raises(LLMConfigError, match="API key"):
        ClaudeAdaptationScanProvider().scan(ScanConfig(repo_path=repo))
