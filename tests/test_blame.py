"""Tests for gitsin.blame — BlameEngine._parse_porcelain parsing logic."""

import pytest
from datetime import datetime, timezone
from gitsin.blame import BlameEngine
from gitsin.models import SinEvent

from tests.conftest import FIXED_EPOCH


# ── Realistic porcelain block ──────────────────────────────────────

SAMPLE_PORCELAIN = """\
aabbccddee00112233445566778899aabbccddee 42 42 1
author Alice Hacker
author-mail <alice@corp.io>
author-time {epoch}
author-tz +0000
committer Alice Hacker
committer-mail <alice@corp.io>
committer-time {epoch}
committer-tz +0000
summary Add config file
filename config/secrets.yaml
\tAWS_KEY=AKIAIOSFODNN7EXAMPLE
""".format(epoch=FIXED_EPOCH)


@pytest.fixture
def blame_engine() -> BlameEngine:
    """BlameEngine with a dummy path — we only test _parse_porcelain, never subprocess."""
    return BlameEngine(target_path="C:\\dummy\\repo")


@pytest.fixture
def sin_for_blame() -> SinEvent:
    return SinEvent(
        rule_id="aws-access-token",
        description="AWS key found",
        file_path="config/secrets.yaml",
        line_number=42,
    )


# ── Happy-path parsing ────────────────────────────────────────────

class TestParsePorcelain:
    def test_commit_hash_extraction(self, blame_engine, sin_for_blame):
        record = blame_engine._parse_porcelain(SAMPLE_PORCELAIN, sin_for_blame)
        assert record.commit_hash == "aabbccddee00112233445566778899aabbccddee"
        assert len(record.commit_hash) == 40

    def test_author_name(self, blame_engine, sin_for_blame):
        record = blame_engine._parse_porcelain(SAMPLE_PORCELAIN, sin_for_blame)
        assert record.actor.name == "Alice Hacker"

    def test_author_email_brackets_stripped(self, blame_engine, sin_for_blame):
        record = blame_engine._parse_porcelain(SAMPLE_PORCELAIN, sin_for_blame)
        assert record.actor.email == "alice@corp.io"
        assert "<" not in record.actor.email
        assert ">" not in record.actor.email

    def test_timestamp_parsed(self, blame_engine, sin_for_blame):
        record = blame_engine._parse_porcelain(SAMPLE_PORCELAIN, sin_for_blame)
        expected_dt = datetime.fromtimestamp(FIXED_EPOCH, tz=timezone.utc)
        assert record.actor.timestamp == expected_dt

    def test_sin_event_preserved(self, blame_engine, sin_for_blame):
        record = blame_engine._parse_porcelain(SAMPLE_PORCELAIN, sin_for_blame)
        assert record.sin is sin_for_blame

    def test_full_record_types(self, blame_engine, sin_for_blame):
        """Verify the returned object is a proper BlameRecord with correct nested types."""
        from gitsin.models import BlameRecord, CommitActor
        record = blame_engine._parse_porcelain(SAMPLE_PORCELAIN, sin_for_blame)
        assert isinstance(record, BlameRecord)
        assert isinstance(record.actor, CommitActor)


# ── Edge cases ─────────────────────────────────────────────────────

class TestParsePorcelainEdgeCases:
    def test_empty_output_raises(self, blame_engine, sin_for_blame):
        with pytest.raises((ValueError, IndexError)):
            blame_engine._parse_porcelain("", sin_for_blame)

    def test_whitespace_only_raises(self, blame_engine, sin_for_blame):
        with pytest.raises((ValueError, IndexError)):
            blame_engine._parse_porcelain("   \n  \n  ", sin_for_blame)

    def test_defaults_when_metadata_missing(self, blame_engine, sin_for_blame):
        """If the porcelain block only has the header line, defaults kick in."""
        minimal = "aabbccddee00112233445566778899aabbccddee 1 1 1\n"
        record = blame_engine._parse_porcelain(minimal, sin_for_blame)
        assert record.actor.name == "Unknown"
        assert record.actor.email == "unknown@company.com"
        # author-time defaults to "0" → epoch 0
        assert record.actor.timestamp == datetime.fromtimestamp(0, tz=timezone.utc)

    def test_email_without_brackets(self, blame_engine, sin_for_blame):
        """If a porcelain block somehow has bare email (no < >), it still works."""
        porcelain = (
            "aabbccddee00112233445566778899aabbccddee 1 1 1\n"
            "author Bob\n"
            "author-mail bob@example.com\n"
            f"author-time {FIXED_EPOCH}\n"
        )
        record = blame_engine._parse_porcelain(porcelain, sin_for_blame)
        assert record.actor.email == "bob@example.com"
