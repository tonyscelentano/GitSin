"""Tests for gitsin.models — Pydantic schema validation."""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError
from gitsin.models import CommitActor, SinEvent, BlameRecord, RiskLedger

from tests.conftest import FIXED_DT


# ── CommitActor ────────────────────────────────────────────────────

class TestCommitActor:
    def test_valid_construction(self, commit_actor):
        assert commit_actor.name == "Alice Hacker"
        assert commit_actor.email == "alice@corp.io"
        assert commit_actor.timestamp == FIXED_DT

    def test_requires_all_fields(self):
        with pytest.raises(ValidationError):
            CommitActor(name="Alice")  # missing email + timestamp


# ── SinEvent ───────────────────────────────────────────────────────

class TestSinEvent:
    def test_defaults(self):
        event = SinEvent(
            rule_id="test-rule",
            description="Test",
            file_path="a.py",
            line_number=1,
        )
        assert event.severity == "HIGH"
        assert event.secret_type is None

    def test_explicit_values(self, sin_event_aws):
        assert sin_event_aws.rule_id == "aws-access-token"
        assert sin_event_aws.severity == "HIGH"
        assert sin_event_aws.secret_type == "aws"
        assert sin_event_aws.line_number == 42

    def test_custom_severity(self):
        event = SinEvent(
            rule_id="x",
            description="x",
            file_path="x",
            line_number=1,
            severity="CRITICAL",
        )
        assert event.severity == "CRITICAL"


# ── BlameRecord ────────────────────────────────────────────────────

class TestBlameRecord:
    def test_composition(self, blame_record, commit_actor, sin_event_aws):
        assert blame_record.commit_hash == "a" * 40
        assert blame_record.actor == commit_actor
        assert blame_record.sin == sin_event_aws

    def test_requires_all_fields(self, commit_actor):
        with pytest.raises(ValidationError):
            BlameRecord(commit_hash="abc123", actor=commit_actor)
            # missing 'sin'


# ── RiskLedger ─────────────────────────────────────────────────────

class TestRiskLedger:
    def test_valid_construction(self, risk_ledger):
        assert risk_ledger.repository_name == "test-repo"
        assert risk_ledger.deterministic_risk_score == 35
        assert len(risk_ledger.violations) == 1

    def test_score_lower_bound(self, blame_record):
        """Score exactly at 0 must be accepted."""
        ledger = RiskLedger(
            repository_name="r",
            scan_timestamp=FIXED_DT,
            deterministic_risk_score=0,
            total_exposure_usd=0,
            violations=[],
        )
        assert ledger.deterministic_risk_score == 0

    def test_score_upper_bound(self, blame_record):
        """Score exactly at 100 must be accepted."""
        ledger = RiskLedger(
            repository_name="r",
            scan_timestamp=FIXED_DT,
            deterministic_risk_score=100,
            total_exposure_usd=0,
            violations=[blame_record],
        )
        assert ledger.deterministic_risk_score == 100

    @pytest.mark.parametrize("bad_score", [-1, 101, 200, -50])
    def test_score_out_of_range_raises(self, bad_score, blame_record):
        with pytest.raises(ValidationError):
            RiskLedger(
                repository_name="r",
                scan_timestamp=FIXED_DT,
                deterministic_risk_score=bad_score,
                total_exposure_usd=0,
                violations=[blame_record],
            )

    def test_telemetry_defaults_to_empty(self, blame_record):
        ledger = RiskLedger(
            repository_name="r",
            scan_timestamp=FIXED_DT,
            deterministic_risk_score=0,
            total_exposure_usd=0,
            violations=[],
        )
        assert ledger.telemetry_activity == []
