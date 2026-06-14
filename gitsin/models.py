from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional


class CommitActor(BaseModel):
    """Git author metadata extracted from `git blame --porcelain`."""
    name: str
    email: str
    timestamp: datetime


class SinEvent(BaseModel):
    """A single secret-leak finding as reported by gitleaks."""
    rule_id: str
    description: str
    file_path: str
    line_number: int
    secret_type: Optional[str] = None
    severity: str = "HIGH"


class BlameRecord(BaseModel):
    """Links a SinEvent to the exact commit and author who introduced it."""
    commit_hash: str
    actor: CommitActor
    sin: SinEvent


class ThreatIndicator(BaseModel):
    """
    A supply chain threat pattern detected in the repository.

    Produced by the heuristic ThreatScanner (Layer 1) or the
    OSV database adapter (Layer 2).  Each indicator represents
    a single file-level match against a known-bad pattern.
    """
    rule_id: str
    name: str
    category: str
    description: str
    file_path: str
    matched_line: Optional[str] = None
    severity: str = "HIGH"
    confidence: str = "high"
    source: str = "bundled"
    references: List[str] = Field(default_factory=list)


class RiskLedger(BaseModel):
    """
    The immutable data contract for a complete GitSin audit.

    Deterministic fields (identical output for identical repo state):
        - deterministic_risk_score, total_exposure_usd, violations,
          threat_indicators

    Non-deterministic fields (vary across runs by design):
        - scan_timestamp: wallclock time of the audit invocation
        - telemetry_activity: local reflog / git log snapshot at scan time
    """
    repository_name: str
    scan_timestamp: datetime
    deterministic_risk_score: int = Field(..., ge=0, le=100)
    total_exposure_usd: int
    violations: List[BlameRecord]
    threat_indicators: List[ThreatIndicator] = Field(default_factory=list)
    compliance_frameworks: List[str] = Field(default_factory=list)
    telemetry_activity: List[str] = Field(default_factory=list)
