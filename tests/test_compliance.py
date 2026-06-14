"""Tests for gitsin.compliance — ComplianceEngine mappings and scoring."""

import pytest
from datetime import datetime, timezone
from gitsin.compliance import ComplianceEngine, FRAMEWORK_MAPPINGS
from gitsin.models import CommitActor, SinEvent, BlameRecord

from tests.conftest import FIXED_DT


@pytest.fixture
def engine() -> ComplianceEngine:
    return ComplianceEngine()


def _make_blame(rule_id: str) -> BlameRecord:
    """Factory to build a minimal BlameRecord for scoring tests."""
    actor = CommitActor(name="X", email="x@x.io", timestamp=FIXED_DT)
    sin = SinEvent(
        rule_id=rule_id,
        description="d",
        file_path="f.py",
        line_number=1,
    )
    return BlameRecord(commit_hash="c" * 40, actor=actor, sin=sin)


# ── Framework mapping ─────────────────────────────────────────────

class TestMapFrameworks:
    @pytest.mark.parametrize(
        "rule_id, expected",
        [
            ("aws-access-token", ["SOC2 CC6.1", "PCI-DSS Req 8"]),
            ("stripe-access-token", ["GDPR Art. 32", "PCI-DSS Req 3"]),
            ("rsa-private-key", ["SOC2 CC6.1", "HIPAA §164.312"]),
            ("generic-api-key", ["SOC2 CC6.1"]),
        ],
    )
    def test_known_rules(self, engine, rule_id, expected):
        assert engine.map_frameworks(rule_id) == expected

    def test_unknown_rule_fallback(self, engine):
        result = engine.map_frameworks("totally-unknown-rule-xyz")
        assert result == ["General Security Best Practices"]

    def test_unknown_rule_uses_mapping_key(self, engine):
        """The fallback list is the same object as FRAMEWORK_MAPPINGS['UNKNOWN_RULE']."""
        result = engine.map_frameworks("nope")
        assert result is FRAMEWORK_MAPPINGS["UNKNOWN_RULE"]


# ── Risk scoring ──────────────────────────────────────────────────

class TestCalculateRiskScore:
    def test_empty_list_returns_zero(self, engine):
        assert engine.calculate_risk_score([]) == 0

    def test_single_critical_aws(self, engine):
        records = [_make_blame("aws-access-token")]
        assert engine.calculate_risk_score(records) == 35

    def test_single_critical_stripe(self, engine):
        records = [_make_blame("stripe-access-token")]
        assert engine.calculate_risk_score(records) == 35

    def test_single_critical_rsa(self, engine):
        records = [_make_blame("rsa-private-key")]
        assert engine.calculate_risk_score(records) == 35

    def test_single_generic(self, engine):
        records = [_make_blame("generic-api-key")]
        assert engine.calculate_risk_score(records) == 15

    @pytest.mark.parametrize(
        "rule_ids, expected",
        [
            # 1 critical (35) + 1 generic (15) = 50
            (["aws-access-token", "generic-api-key"], 50),
            # 2 critical = 70
            (["aws-access-token", "stripe-access-token"], 70),
            # 3 critical = min(105, 100) = 100
            (["aws-access-token", "stripe-access-token", "rsa-private-key"], 100),
            # 7 generic = min(105, 100) = 100
            (["generic-api-key"] * 7, 100),
        ],
    )
    def test_multi_finding_scores(self, engine, rule_ids, expected):
        records = [_make_blame(r) for r in rule_ids]
        assert engine.calculate_risk_score(records) == expected

    def test_cap_at_100(self, engine):
        """Massive number of findings must not exceed 100."""
        records = [_make_blame("aws-access-token")] * 20
        assert engine.calculate_risk_score(records) == 100

    def test_order_independence(self, engine):
        """Score is additive so order must not matter."""
        forward = [_make_blame("aws-access-token"), _make_blame("generic-api-key")]
        reverse = list(reversed(forward))
        assert engine.calculate_risk_score(forward) == engine.calculate_risk_score(reverse)

    def test_case_insensitive_matching(self, engine):
        """rule_id is lowercased internally — verify uppercase variant still scores as critical."""
        records = [_make_blame("AWS-ACCESS-TOKEN")]
        assert engine.calculate_risk_score(records) == 35
