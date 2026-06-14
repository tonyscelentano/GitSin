"""
ThreatScanner — Layer 1 heuristic supply chain threat detection.

Walks the target repository's file tree and applies bundled glob + regex
rules from ``threat_rules.json``.  Every rule targets specific *behaviors*
(pipe-to-shell, base64 decode, env exfiltration) rather than mere
presence, minimising false positives.

This module is fully offline and deterministic: same repo state in,
same findings out.
"""

import json
import re
from pathlib import Path, PurePosixPath
from typing import List, Optional

from gitsin.models import ThreatIndicator

# ---------------------------------------------------------------------------
# Rule loading — happens once at import time, from the bundled JSON
# ---------------------------------------------------------------------------

_RULES_PATH = Path(__file__).parent / "threat_rules.json"


def _load_rules() -> list[dict]:
    """Load the bundled threat rules from the JSON file shipped with gitsin."""
    with open(_RULES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


_RULES: list[dict] = _load_rules()

# Pre-compile content patterns for performance.
_COMPILED_RULES: list[tuple[dict, Optional[re.Pattern]]] = []
for rule in _RULES:
    pattern = rule.get("content_pattern")
    compiled = re.compile(pattern, re.IGNORECASE) if pattern else None
    _COMPILED_RULES.append((rule, compiled))


# ---------------------------------------------------------------------------
# File tree walking helpers
# ---------------------------------------------------------------------------

# Directories that should never be scanned.
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
}

# Maximum file size to content-scan (256 KB).  Anything larger is
# almost certainly not a manifest or config file.
_MAX_CONTENT_BYTES = 256 * 1024


def _walk_repo(root: Path):
    """Yield ``Path`` objects for every file under *root*, skipping
    directories in ``_SKIP_DIRS``."""
    for child in root.iterdir():
        if child.is_dir():
            if child.name in _SKIP_DIRS:
                continue
            yield from _walk_repo(child)
        elif child.is_file():
            yield child


def _matches_glob(file_rel: str, globs: list[str]) -> bool:
    """Return ``True`` if *file_rel* matches any of the *globs*.

    Handles recursive ``**`` patterns correctly for relative paths.
    ``PurePosixPath.match()`` treats ``**`` as requiring at least one
    directory level, so for paths near the repo root (e.g.
    ``.vscode/tasks.json``), we also try the glob with its leading
    ``**/`` stripped (e.g. ``.vscode/tasks.json``).
    """
    p = PurePosixPath(file_rel)
    for g in globs:
        if p.match(g):
            return True
        # Fallback: if the glob starts with **/, also try matching
        # without that prefix for root-relative paths.
        if g.startswith("**/"):
            stripped = g[3:]  # Remove leading "**/".
            if p.match(stripped):
                return True
    return False


def _is_allowlisted(line: str, allowlist: list[str]) -> bool:
    """Return ``True`` if *line* contains any allowlist pattern."""
    for pattern in allowlist:
        if pattern in line:
            return True
    return False


# ---------------------------------------------------------------------------
# ThreatScanner
# ---------------------------------------------------------------------------

class ThreatScanner:
    """
    Scans a local repository for supply chain threat indicators using
    bundled heuristic rules.

    Two matching modes per rule:

    1. **Presence-only** (``content_pattern`` is null):
       Triggers if any file matching ``target_globs`` exists.

    2. **Content match** (``content_pattern`` is set):
       Reads files matching ``target_globs`` and searches for the
       regex pattern.  If the matched line is also in the
       ``allowlist_patterns``, the finding is suppressed.
    """

    def __init__(self, target_path: str):
        self.repo_root = Path(target_path).resolve()

    def scan(self) -> List[ThreatIndicator]:
        """Walk the repository and apply all heuristic rules.

        Returns a list of :class:`ThreatIndicator` for each match.
        """
        if not self.repo_root.exists():
            return []

        indicators: list[ThreatIndicator] = []

        # Collect all files once, compute relative paths.
        file_list: list[tuple[Path, str]] = []
        for fpath in _walk_repo(self.repo_root):
            rel = fpath.relative_to(self.repo_root).as_posix()
            file_list.append((fpath, rel))

        for rule, compiled_re in _COMPILED_RULES:
            globs = rule["target_globs"]
            allowlist = rule.get("allowlist_patterns", [])

            for fpath, rel in file_list:
                if not _matches_glob(rel, globs):
                    continue

                # --- Presence-only rule ---
                if compiled_re is None:
                    indicators.append(self._build_indicator(rule, rel))
                    continue

                # --- Content-matching rule ---
                if fpath.stat().st_size > _MAX_CONTENT_BYTES:
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                for line in content.splitlines():
                    match = compiled_re.search(line)
                    if match and not _is_allowlisted(line, allowlist):
                        indicators.append(
                            self._build_indicator(
                                rule, rel, matched_line=line.strip()
                            )
                        )
                        # One match per file per rule is sufficient.
                        break

        return indicators

    # -----------------------------------------------------------------------
    # Indicator construction
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_indicator(
        rule: dict,
        file_path: str,
        matched_line: Optional[str] = None,
    ) -> ThreatIndicator:
        return ThreatIndicator(
            rule_id=rule["id"],
            name=rule["name"],
            category=rule["category"],
            description=rule["description"],
            file_path=file_path,
            matched_line=matched_line,
            severity=rule.get("severity", "HIGH"),
            confidence=rule.get("confidence", "high"),
            source="bundled",
            references=rule.get("references", []),
        )
