import subprocess
from pathlib import Path
from typing import List

# Timeout for telemetry git commands (seconds).
_TELEMETRY_TIMEOUT_SECONDS = 15


class TelemetryEngine:
    """
    The "Voyeur Protocol" — interrogates local git history to identify
    who has interacted with the repository since a sin was committed.

    NOTE: Telemetry output is **intentionally non-deterministic**.
    The ``telemetry_activity`` field in :class:`RiskLedger` reflects
    the reflog/log state at scan time, which changes with every
    local git interaction.  This is the one field in the ledger
    that is not reproducible across runs by design.
    """

    def __init__(self, target_path: str):
        self.repo_root = Path(target_path).resolve()

    def get_recent_activity(self) -> List[str]:
        """
        Attempts to use ``git reflog`` to detect recent repository activity locally.
        Falls back to standard ``git log`` metadata if reflog is empty or unavailable.
        This answers: 'Who has touched this repo locally since the sin was committed?'
        """
        try:
            # Pull the 5 most recent reflog actions to identify local voyeurs/cloners
            command = ["git", "reflog", "--date=iso", "-n", "5"]
            result = subprocess.run(
                command,
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                check=True,
                timeout=_TELEMETRY_TIMEOUT_SECONDS,
            )

            lines = result.stdout.strip().split("\n")
            activity = [line for line in lines if line]

            # If reflog is empty (e.g. freshly cloned with no local changes), fallback to git log
            if not activity:
                return self._fallback_git_log()

            return activity

        except subprocess.TimeoutExpired:
            return ["[!] Telemetry degraded: git reflog timed out."]
        except subprocess.CalledProcessError:
            return ["[!] Telemetry degraded: Local reflog unavailable."]

    def _fallback_git_log(self) -> List[str]:
        try:
            command = ["git", "log", "-n", "3", "--oneline", "--format=%cd - %an : %s"]
            result = subprocess.run(
                command,
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                check=True,
                timeout=_TELEMETRY_TIMEOUT_SECONDS,
            )
            lines = result.stdout.strip().split("\n")
            return [line for line in lines if line]
        except subprocess.TimeoutExpired:
            return ["[!] Telemetry completely degraded: git log timed out."]
        except subprocess.CalledProcessError:
            return ["[!] Telemetry completely degraded: Git log unavailable."]
