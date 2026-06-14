import json
from importlib.metadata import version as pkg_version, PackageNotFoundError
from .models import RiskLedger
from . import html_report


def _get_version() -> str:
    """Resolve the installed package version, falling back to 'dev' for editable installs."""
    try:
        return pkg_version("gitsin")
    except PackageNotFoundError:
        return "dev"


class ExportManager:
    @staticmethod
    def export_json(ledger: RiskLedger) -> str:
        """Utilizes Pydantic's native model_dump_json for immutable serialization."""
        return ledger.model_dump_json(indent=2)

    @staticmethod
    def export_html(ledger: RiskLedger) -> str:
        """Render a self-contained HTML executive summary report.

        The returned string is a complete ``<!DOCTYPE html>`` document
        with all CSS and JS inlined, safe for writing to a ``.html``
        file.  All untrusted data is XSS-sanitized.
        """
        return html_report.render(ledger)

    @staticmethod
    def export_sarif(ledger: RiskLedger) -> str:
        """Constructs a SARIF v2.1.0 payload from the RiskLedger."""
        # Build an ordered rule list and a rule_id -> index lookup.
        rules_map: dict[str, dict] = {}
        rule_index_lookup: dict[str, int] = {}

        for record in ledger.violations:
            rule_id = record.sin.rule_id
            if rule_id not in rules_map:
                idx = len(rules_map)
                rules_map[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": record.sin.description},
                    "defaultConfiguration": {
                        "level": "error" if record.sin.severity.lower() in ["high", "critical"] else "warning"
                    },
                }
                rule_index_lookup[rule_id] = idx

        sarif_rules = list(rules_map.values())

        # Map results — each result carries a ruleIndex for SARIF spec compliance.
        results = []
        for record in ledger.violations:
            result = {
                "ruleId": record.sin.rule_id,
                "ruleIndex": rule_index_lookup[record.sin.rule_id],
                "level": rules_map[record.sin.rule_id]["defaultConfiguration"]["level"],
                "message": {
                    "text": (
                        f"{record.sin.description}\n"
                        f"Responsible: {record.actor.name} <{record.actor.email}>\n"
                        f"Commit: {record.commit_hash}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": record.sin.file_path,
                            },
                            "region": {
                                "startLine": record.sin.line_number,
                            },
                        }
                    }
                ],
                "properties": {
                    "commitActor": record.actor.name,
                    "commitEmail": record.actor.email,
                    "commitHash": record.commit_hash,
                    "commitTimestamp": record.actor.timestamp.isoformat(),
                },
            }
            results.append(result)

        sarif_payload = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "GitSin",
                            "version": _get_version(),
                            "informationUri": "https://github.com/RepoReckoning/gitsin",
                            "rules": sarif_rules,
                        },
                        "extensions": _build_threat_extension(ledger),
                    },
                    "results": results + _build_threat_results(ledger),
                }
            ],
        }

        return json.dumps(sarif_payload, indent=2)


def _build_threat_extension(ledger: RiskLedger) -> list[dict]:
    """Build a SARIF tool extension for supply chain threat indicators."""
    if not ledger.threat_indicators:
        return []

    rules_map: dict[str, dict] = {}
    for ind in ledger.threat_indicators:
        if ind.rule_id not in rules_map:
            rules_map[ind.rule_id] = {
                "id": ind.rule_id,
                "shortDescription": {"text": ind.name},
                "fullDescription": {"text": ind.description},
                "defaultConfiguration": {
                    "level": "error" if ind.severity.upper() in ["HIGH", "CRITICAL"] else "warning"
                },
                "properties": {
                    "category": ind.category,
                    "confidence": ind.confidence,
                },
            }

    return [
        {
            "name": "GitSin-ThreatScanner",
            "version": _get_version(),
            "rules": list(rules_map.values()),
        }
    ]


def _build_threat_results(ledger: RiskLedger) -> list[dict]:
    """Build SARIF results for supply chain threat indicators."""
    results = []
    for ind in ledger.threat_indicators:
        result = {
            "ruleId": ind.rule_id,
            "level": "error" if ind.severity.upper() in ["HIGH", "CRITICAL"] else "warning",
            "message": {
                "text": ind.description,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": ind.file_path,
                        },
                    }
                }
            ],
            "properties": {
                "category": ind.category,
                "confidence": ind.confidence,
                "source": ind.source,
                "matchedLine": ind.matched_line,
            },
        }
        results.append(result)
    return results
