from typing import List
from .models import BlameRecord, ThreatIndicator

# Static mapping for offline-first determinism
FRAMEWORK_MAPPINGS = {
    "aws-access-token": ["SOC2 CC6.1", "PCI-DSS Req 8"],
    "stripe-access-token": ["GDPR Art. 32", "PCI-DSS Req 3"],
    "generic-api-key": ["SOC2 CC6.1"],
    "rsa-private-key": ["SOC2 CC6.1", "HIPAA §164.312"],
    "UNKNOWN_RULE": ["General Security Best Practices"],
}

# Supply chain threat scoring weights.
# A single CRITICAL supply chain indicator is more dangerous than a
# single leaked API key because it implies active adversarial presence.
_THREAT_SCORE_WEIGHTS = {
    ("CRITICAL", "high"): 40,
    ("CRITICAL", "medium"): 30,
    ("HIGH", "high"): 25,
    ("HIGH", "medium"): 20,
    ("HIGH", "low"): 10,
    ("MEDIUM", "high"): 15,
    ("MEDIUM", "medium"): 10,
    ("MEDIUM", "low"): 5,
}
_THREAT_SCORE_DEFAULT = 5


class ComplianceEngine:
    """
    Handles regulatory mapping and deterministic risk scoring.

    Scoring model (additive, order-independent, capped at 100):

    Secret leak scoring:
      - Critical secrets (AWS, Stripe, RSA key material): +35 per finding
      - All other secrets (generic API keys, etc.):      +15 per finding

    Supply chain threat scoring:
      - CRITICAL / high confidence: +40 per indicator
      - HIGH / medium confidence:   +20 per indicator
      - LOW / info indicators:      +5  per indicator

    CAVEAT: Rule classification uses substring matching on the lowercased
    rule_id.  A hypothetical rule containing "aws" as a substring (e.g.
    "drawstring-token") would be scored as critical.  If the gitleaks
    rule set expands significantly, consider switching to an explicit
    allowlist of critical rule IDs.
    """

    def __init__(self):
        self.framework_map = FRAMEWORK_MAPPINGS

    def map_frameworks(self, rule_id: str) -> List[str]:
        """Maps a gitleaks rule ID to regulatory compliance frameworks."""
        return self.framework_map.get(rule_id, self.framework_map["UNKNOWN_RULE"])

    def calculate_risk_score(
        self,
        blame_records: List[BlameRecord],
        threat_indicators: List[ThreatIndicator] | None = None,
    ) -> int:
        """
        Calculates a deterministic risk score from 0-100.

        The score is purely additive (order-independent) and capped at 100.
        Given identical inputs, the output is always identical.

        Args:
            blame_records: Secret-leak findings with blame attribution.
            threat_indicators: Supply chain threat indicators (optional).
        """
        score = 0

        # Secret leak scoring
        for record in blame_records:
            rule_id = record.sin.rule_id.lower()
            if "aws" in rule_id or "stripe" in rule_id or "rsa" in rule_id:
                score += 35  # Critical entropy
            else:
                score += 15  # High entropy

        # Supply chain threat scoring
        for indicator in (threat_indicators or []):
            key = (indicator.severity.upper(), indicator.confidence.lower())
            score += _THREAT_SCORE_WEIGHTS.get(key, _THREAT_SCORE_DEFAULT)

        return min(score, 100)  # Cap at 100% risk
