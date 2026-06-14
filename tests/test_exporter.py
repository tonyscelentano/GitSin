"""Tests for gitsin.exporter — ExportManager JSON and SARIF output."""

import json
import pytest
from unittest.mock import patch
from gitsin.exporter import ExportManager, _get_version
from gitsin.models import RiskLedger


# ── export_json ────────────────────────────────────────────────────

class TestExportJson:
    def test_returns_valid_json(self, risk_ledger):
        raw = ExportManager.export_json(risk_ledger)
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_round_trips_through_pydantic(self, risk_ledger):
        """JSON output must deserialize back into an identical RiskLedger."""
        raw = ExportManager.export_json(risk_ledger)
        restored = RiskLedger.model_validate_json(raw)
        assert restored.repository_name == risk_ledger.repository_name
        assert restored.deterministic_risk_score == risk_ledger.deterministic_risk_score
        assert len(restored.violations) == len(risk_ledger.violations)

    def test_contains_expected_keys(self, risk_ledger):
        parsed = json.loads(ExportManager.export_json(risk_ledger))
        expected_keys = {
            "repository_name",
            "scan_timestamp",
            "deterministic_risk_score",
            "total_exposure_usd",
            "violations",
            "threat_indicators",
            "compliance_frameworks",
            "telemetry_activity",
        }
        assert expected_keys == set(parsed.keys())

    def test_two_violations(self, risk_ledger_two):
        parsed = json.loads(ExportManager.export_json(risk_ledger_two))
        assert len(parsed["violations"]) == 2


# ── export_sarif ───────────────────────────────────────────────────

class TestExportSarif:
    def test_returns_valid_json(self, risk_ledger):
        raw = ExportManager.export_sarif(risk_ledger)
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_sarif_version(self, risk_ledger):
        parsed = json.loads(ExportManager.export_sarif(risk_ledger))
        assert parsed["version"] == "2.1.0"

    def test_sarif_schema(self, risk_ledger):
        parsed = json.loads(ExportManager.export_sarif(risk_ledger))
        assert "$schema" in parsed
        assert "sarif-schema-2.1.0" in parsed["$schema"]

    def test_sarif_has_runs(self, risk_ledger):
        parsed = json.loads(ExportManager.export_sarif(risk_ledger))
        assert "runs" in parsed
        assert len(parsed["runs"]) == 1

    def test_sarif_driver_info(self, risk_ledger):
        parsed = json.loads(ExportManager.export_sarif(risk_ledger))
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["name"] == "GitSin"
        assert "version" in driver
        assert "rules" in driver

    def test_sarif_rules_match_violations(self, risk_ledger_two):
        """Rules array must contain exactly the distinct rule_ids from violations."""
        parsed = json.loads(ExportManager.export_sarif(risk_ledger_two))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        expected_ids = {v.sin.rule_id for v in risk_ledger_two.violations}
        assert rule_ids == expected_ids

    def test_sarif_result_rule_index(self, risk_ledger):
        parsed = json.loads(ExportManager.export_sarif(risk_ledger))
        results = parsed["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleIndex"] == 0
        assert results[0]["ruleId"] == "aws-access-token"

    def test_sarif_result_rule_index_multi(self, risk_ledger_two):
        """Two distinct rules: ruleIndex 0 and 1."""
        parsed = json.loads(ExportManager.export_sarif(risk_ledger_two))
        results = parsed["runs"][0]["results"]
        indices = {r["ruleIndex"] for r in results}
        assert indices == {0, 1}

    def test_sarif_result_locations(self, risk_ledger):
        parsed = json.loads(ExportManager.export_sarif(risk_ledger))
        loc = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "config/secrets.yaml"
        assert loc["region"]["startLine"] == 42

    def test_sarif_result_level(self, risk_ledger):
        parsed = json.loads(ExportManager.export_sarif(risk_ledger))
        assert parsed["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_result_properties(self, risk_ledger):
        parsed = json.loads(ExportManager.export_sarif(risk_ledger))
        props = parsed["runs"][0]["results"][0]["properties"]
        assert props["commitActor"] == "Alice Hacker"
        assert props["commitEmail"] == "alice@corp.io"
        assert props["commitHash"] == "a" * 40


# ── _get_version helper ───────────────────────────────────────────

class TestGetVersion:
    def test_returns_dev_when_not_installed(self):
        from importlib.metadata import PackageNotFoundError
        with patch("gitsin.exporter.pkg_version", side_effect=PackageNotFoundError):
            assert _get_version() == "dev"

    def test_returns_real_version_when_installed(self):
        with patch("gitsin.exporter.pkg_version", return_value="1.2.3"):
            assert _get_version() == "1.2.3"
