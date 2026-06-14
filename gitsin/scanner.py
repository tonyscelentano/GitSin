import json
import subprocess
import shutil
import tempfile
from pathlib import Path
from typing import List
from gitsin.models import SinEvent

# Subprocess timeout for gitleaks scan (seconds).
# Large repos may take time; 120s is generous for local scans.
_SCAN_TIMEOUT_SECONDS = 120


class GitleaksOrchestrator:
    def __init__(self, target_path: str):
        self.target_path = Path(target_path).resolve()

    def _get_gitleaks_path(self):
        """Resolve gitleaks binary, checking PyInstaller bundle first, then PATH."""
        import sys
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            # Running as compiled PyInstaller executable
            bundled = Path(sys._MEIPASS) / "gitleaks_bin" / "gitleaks.exe"
            if bundled.exists():
                return str(bundled)
        
        # Fallback to system PATH
        return shutil.which("gitleaks")

    def verify_binary(self) -> bool:
        """Verify that gitleaks is installed and accessible."""
        return self._get_gitleaks_path() is not None

    def execute_scan(self) -> List[SinEvent]:
        """Executes gitleaks detect against the target path and parses findings.

        If gitleaks is not installed, returns an empty list and sets
        ``self.gitleaks_missing`` to ``True`` so the caller can warn
        the user without crashing.
        """
        self.gitleaks_missing = False
        if not self.verify_binary():
            self.gitleaks_missing = True
            return []

        if not self.target_path.exists():
            raise FileNotFoundError(f"[🚨] Target path does not exist: {self.target_path}")

        # Write the report to an OS-managed temp file so plaintext secrets never
        # touch the target repository, even transiently.
        fd, report_path = tempfile.mkstemp(prefix="gitsin_", suffix=".json")
        try:
            # Close the fd immediately — gitleaks writes by path, not descriptor.
            import os
            os.close(fd)

            # Gitleaks exit codes: 0 = clean, 1 = leaks found, ≥2 = real error.
            command = [
                self._get_gitleaks_path(),
                "detect",
                f"--source={self.target_path}",
                f"--report-path={report_path}",
                "--report-format=json",
            ]

            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=_SCAN_TIMEOUT_SECONDS,
            )

            if proc.returncode not in (0, 1):
                raise RuntimeError(
                    f"gitleaks exited with code {proc.returncode}: "
                    f"{proc.stderr.strip()}"
                )

            return self._parse_report(Path(report_path))
        finally:
            # Always clean up — even on crash the temp file is removed.
            report = Path(report_path)
            if report.exists():
                report.unlink()

    def _parse_report(self, report_path: Path) -> List[SinEvent]:
        """Reads the gitleaks JSON output and converts it to strict Pydantic models."""
        if not report_path.exists() or report_path.stat().st_size == 0:
            return []

        with open(report_path, "r", encoding="utf-8") as f:
            raw_leaks = json.load(f)

        sin_events = []
        for leak in raw_leaks:
            # Map Gitleaks payload keys natively to gitsin.models.SinEvent.
            # Tags provides richer type info than duplicating RuleID.
            tags = leak.get("Tags")
            secret_type = ", ".join(tags) if isinstance(tags, list) and tags else None

            event = SinEvent(
                rule_id=leak.get("RuleID", "UNKNOWN_RULE"),
                description=leak.get("Description", "No description provided."),
                file_path=leak.get("File", ""),
                line_number=int(leak.get("StartLine", 1)),
                secret_type=secret_type,
                severity="HIGH",
            )
            sin_events.append(event)

        return sin_events
