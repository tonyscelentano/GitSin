"""Tests for gitsin.scanner — GitleaksOrchestrator._parse_report only.

We NEVER invoke execute_scan or touch the gitleaks binary.
All tests use pytest's tmp_path fixture to write ephemeral JSON files.
"""

import json
import pytest
from pathlib import Path
from gitsin.scanner import GitleaksOrchestrator
from gitsin.models import SinEvent


@pytest.fixture
def orchestrator() -> GitleaksOrchestrator:
    return GitleaksOrchestrator(target_path="C:\\dummy\\repo")


# ── Sample gitleaks JSON payloads ──────────────────────────────────

SINGLE_LEAK = [
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Key ID",
        "File": "config/secrets.yaml",
        "StartLine": 10,
        "Tags": ["key", "aws"],
    }
]

MULTI_LEAK = [
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Key",
        "File": "a.py",
        "StartLine": 5,
        "Tags": ["key", "aws"],
    },
    {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "b.py",
        "StartLine": 20,
        "Tags": [],
    },
    {
        "RuleID": "stripe-access-token",
        "Description": "Stripe key",
        "File": "c.py",
        "StartLine": 99,
        "Tags": None,
    },
]

LEAK_NO_OPTIONAL = [
    {
        # Missing RuleID, Description, Tags — exercises default fallbacks
        "File": "unknown.txt",
        "StartLine": 1,
    }
]


def _write_report(tmp_path: Path, payload: list) -> Path:
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    return report


# ── Happy-path ─────────────────────────────────────────────────────

class TestParseReport:
    def test_single_finding(self, orchestrator, tmp_path):
        path = _write_report(tmp_path, SINGLE_LEAK)
        events = orchestrator._parse_report(path)
        assert len(events) == 1
        e = events[0]
        assert isinstance(e, SinEvent)
        assert e.rule_id == "aws-access-token"
        assert e.description == "AWS Access Key ID"
        assert e.file_path == "config/secrets.yaml"
        assert e.line_number == 10
        assert e.severity == "HIGH"

    def test_tags_mapped_to_secret_type(self, orchestrator, tmp_path):
        path = _write_report(tmp_path, SINGLE_LEAK)
        events = orchestrator._parse_report(path)
        # Tags ["key", "aws"] → "key, aws"
        assert events[0].secret_type == "key, aws"

    def test_empty_tags_gives_none(self, orchestrator, tmp_path):
        path = _write_report(tmp_path, MULTI_LEAK)
        events = orchestrator._parse_report(path)
        # Second entry has Tags: [] → None
        assert events[1].secret_type is None

    def test_none_tags_gives_none(self, orchestrator, tmp_path):
        path = _write_report(tmp_path, MULTI_LEAK)
        events = orchestrator._parse_report(path)
        # Third entry has Tags: None → None
        assert events[2].secret_type is None

    def test_multiple_findings(self, orchestrator, tmp_path):
        path = _write_report(tmp_path, MULTI_LEAK)
        events = orchestrator._parse_report(path)
        assert len(events) == 3
        assert events[0].rule_id == "aws-access-token"
        assert events[1].rule_id == "generic-api-key"
        assert events[2].rule_id == "stripe-access-token"

    def test_missing_optional_fields_use_defaults(self, orchestrator, tmp_path):
        path = _write_report(tmp_path, LEAK_NO_OPTIONAL)
        events = orchestrator._parse_report(path)
        assert len(events) == 1
        e = events[0]
        assert e.rule_id == "UNKNOWN_RULE"
        assert e.description == "No description provided."
        assert e.secret_type is None


# ── Empty / missing report ─────────────────────────────────────────

class TestParseReportEdgeCases:
    def test_nonexistent_file_returns_empty(self, orchestrator, tmp_path):
        missing = tmp_path / "does_not_exist.json"
        assert orchestrator._parse_report(missing) == []

    def test_empty_file_returns_empty(self, orchestrator, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text("", encoding="utf-8")
        assert orchestrator._parse_report(empty) == []

    def test_empty_array_returns_empty(self, orchestrator, tmp_path):
        path = _write_report(tmp_path, [])
        assert orchestrator._parse_report(path) == []
