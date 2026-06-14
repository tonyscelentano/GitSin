"""Shared pytest fixtures for the GitSin test suite.

All timestamps are pinned to a deterministic epoch value so tests
never depend on wallclock time.
"""

import pytest
from datetime import datetime, timezone
from gitsin.models import CommitActor, SinEvent, BlameRecord, RiskLedger


# ── Deterministic timestamp used across every fixture ──────────────
FIXED_EPOCH = 1_700_000_000  # 2023-11-14T22:13:20 UTC
FIXED_DT = datetime.fromtimestamp(FIXED_EPOCH, tz=timezone.utc)


@pytest.fixture
def commit_actor() -> CommitActor:
    return CommitActor(
        name="Alice Hacker",
        email="alice@corp.io",
        timestamp=FIXED_DT,
    )


@pytest.fixture
def sin_event_aws() -> SinEvent:
    return SinEvent(
        rule_id="aws-access-token",
        description="AWS Access Key detected",
        file_path="config/secrets.yaml",
        line_number=42,
        secret_type="aws",
        severity="HIGH",
    )


@pytest.fixture
def sin_event_generic() -> SinEvent:
    return SinEvent(
        rule_id="generic-api-key",
        description="Generic API key detected",
        file_path="src/app.py",
        line_number=7,
    )


@pytest.fixture
def blame_record(commit_actor, sin_event_aws) -> BlameRecord:
    return BlameRecord(
        commit_hash="a" * 40,
        actor=commit_actor,
        sin=sin_event_aws,
    )


@pytest.fixture
def blame_record_generic(commit_actor, sin_event_generic) -> BlameRecord:
    return BlameRecord(
        commit_hash="b" * 40,
        actor=commit_actor,
        sin=sin_event_generic,
    )


@pytest.fixture
def risk_ledger(blame_record) -> RiskLedger:
    return RiskLedger(
        repository_name="test-repo",
        scan_timestamp=FIXED_DT,
        deterministic_risk_score=35,
        total_exposure_usd=50_000,
        violations=[blame_record],
        telemetry_activity=["abc1234 HEAD@{0}: clone: from https://example.com"],
    )


@pytest.fixture
def risk_ledger_two(blame_record, blame_record_generic) -> RiskLedger:
    """Ledger with two violations (one critical, one generic)."""
    return RiskLedger(
        repository_name="multi-repo",
        scan_timestamp=FIXED_DT,
        deterministic_risk_score=50,
        total_exposure_usd=120_000,
        violations=[blame_record, blame_record_generic],
    )
