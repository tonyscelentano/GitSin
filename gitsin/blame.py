import subprocess
from pathlib import Path
from datetime import datetime, timezone
from gitsin.models import BlameRecord, CommitActor, SinEvent

class BlameEngine:
    def __init__(self, target_path: str):
        self.repo_root = Path(target_path).resolve()

    def attribute_sin(self, sin: SinEvent) -> BlameRecord:
        """Executes git blame --porcelain on a specific line of a file to extract attribution data."""
        # Ensure we run the git command inside the actual repository directory context
        command = [
            "git",
            "blame",
            "--porcelain",
            "-L",
            f"{sin.line_number},{sin.line_number}",
            sin.file_path
        ]

        try:
            result = subprocess.run(
                command,
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            return self._parse_porcelain(result.stdout, sin)
        except subprocess.CalledProcessError as e:
            # git blame exits 128 on untracked files
            if e.returncode == 128:
                return BlameRecord(
                    commit_hash="UNCOMMITTED",
                    actor=CommitActor(
                        name="Local Developer",
                        email="untracked@local",
                        timestamp=datetime.now(timezone.utc)
                    ),
                    sin=sin
                )
            raise

    def _parse_porcelain(self, porcelain_output: str, sin: SinEvent) -> BlameRecord:
        """Parses the raw structured string block returned by git blame --porcelain."""
        lines = porcelain_output.strip().split("\n")
        if not lines or not lines[0].strip():
            raise ValueError("Empty output received from git blame porcelain parsing module.")

        # Line 1 always starts with the 40-character commit hash
        first_line_tokens = lines[0].split()
        commit_hash = first_line_tokens[0]

        # Initialize tracking dict for target fields
        metadata = {
            "author": "Unknown",
            "author-mail": "unknown@company.com",
            "author-time": "0"
        }

        # Parse key-value mappings out of the porcelain payload block
        for line in lines[1:]:
            for key in metadata.keys():
                if line.startswith(f"{key} "):
                    # Strip the key prefix and extract the value
                    metadata[key] = line[len(key) + 1:].strip()

        # Clean the email formatting from '<user@email.com>' to 'user@email.com'
        email_clean = metadata["author-mail"].lstrip("<").rstrip(">")
        
        # Convert unix epoch timestamp securely to UTC datetime object
        timestamp_dt = datetime.fromtimestamp(int(metadata["author-time"]), tz=timezone.utc)

        actor = CommitActor(
            name=metadata["author"],
            email=email_clean,
            timestamp=timestamp_dt
        )

        return BlameRecord(
            commit_hash=commit_hash,
            actor=actor,
            sin=sin
        )
