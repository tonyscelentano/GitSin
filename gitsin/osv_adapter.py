"""
OSV Adapter — Layer 2 hydrated threat intelligence.

Manages the local clone of the OpenSSF Malicious Packages database,
compiles a lightweight lookup index from the raw OSV JSON shards, and
cross-references dependency manifests in the target repository against
known-malicious package names.

The design contract:
  - ``update_db()`` touches the network exactly once (git clone/pull).
  - ``compile_index()`` walks the 30K+ JSON files exactly once.
  - ``load_compiled_index()`` reads a single <5MB JSON file.
  - ``check_manifests()`` does O(1) dict lookups per package name.

This module is the only component in GitSin that touches the network,
and only when the user explicitly runs ``gitsin update-db``.
"""

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import List, Optional

from .models import ThreatIndicator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSV_REPO_URL = "https://github.com/ossf/malicious-packages.git"

DEFAULT_DB_DIR = Path.home() / ".gitsin" / "databases" / "malicious-packages"
DEFAULT_INDEX_PATH = Path.home() / ".gitsin" / "compiled_osv_index.json"

# Subprocess timeout for git operations (seconds).
_GIT_CLONE_TIMEOUT = 600   # 10 min — initial clone can be large.
_GIT_PULL_TIMEOUT = 120    # 2 min — incremental pulls are fast.

# ---------------------------------------------------------------------------
# Database management — clone / pull / compile / persist
# ---------------------------------------------------------------------------


def clone_or_pull(db_path: Path | None = None) -> str:
    """Clone or update the OpenSSF malicious-packages repository.

    Args:
        db_path: Local directory for the clone.  Defaults to
            ``~/.gitsin/databases/malicious-packages/``.

    Returns:
        A human-readable status message.

    Raises:
        RuntimeError: If the git command fails.
    """
    db_path = Path(db_path) if db_path else DEFAULT_DB_DIR

    if (db_path / ".git").is_dir():
        # Existing clone — pull updates.
        result = subprocess.run(
            ["git", "-C", str(db_path), "pull", "--ff-only"],
            capture_output=True, text=True, timeout=_GIT_PULL_TIMEOUT,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git pull failed (exit {result.returncode}): {result.stderr.strip()}"
            )
        return f"Updated existing database at {db_path}"
    else:
        # Fresh clone — shallow for bandwidth efficiency.
        db_path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", OSV_REPO_URL, str(db_path)],
            capture_output=True, text=True, timeout=_GIT_CLONE_TIMEOUT,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git clone failed (exit {result.returncode}): {result.stderr.strip()}"
            )
        return f"Cloned database to {db_path}"


def compile_index(db_path: Path | None = None) -> dict:
    """Walk the raw OSV JSON files and build a compiled lookup index.

    Scans the ``malicious/`` subdirectory tree of the cloned repository,
    parses each ``.json`` file, and extracts ecosystem + package name +
    advisory metadata.

    Args:
        db_path: Root of the cloned malicious-packages repository.

    Returns:
        A dict with structure::

            {
                "metadata": {"compiled_at": ..., "total_advisories": ..., "source": ...},
                "index": {
                    "npm": {
                        "malicious-pkg": [
                            {"id": "MAL-2024-1234", "summary": "..."}
                        ]
                    },
                    ...
                }
            }
    """
    db_path = Path(db_path) if db_path else DEFAULT_DB_DIR

    # The malicious packages live under malicious/ in the repo root.
    malicious_root = db_path / "malicious"
    if not malicious_root.is_dir():
        # Fallback: some repo structures put them at the root.
        malicious_root = db_path

    index: dict[str, dict[str, list[dict]]] = {}
    total = 0
    errors = 0

    for json_path in malicious_root.rglob("*.json"):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                osv = json.load(f)
        except (json.JSONDecodeError, OSError):
            errors += 1
            continue

        advisory_id = osv.get("id", "")
        summary = osv.get("summary", "")

        for affected in osv.get("affected", []):
            pkg = affected.get("package", {})
            ecosystem = pkg.get("ecosystem", "").lower()
            name = pkg.get("name", "")

            if not ecosystem or not name:
                continue

            # Normalize ecosystem names for consistent lookup.
            ecosystem = _normalize_ecosystem(ecosystem)

            if ecosystem not in index:
                index[ecosystem] = {}
            if name not in index[ecosystem]:
                index[ecosystem][name] = []

            index[ecosystem][name].append({
                "id": advisory_id,
                "summary": summary[:200],  # Truncate for index size.
            })
            total += 1

    return {
        "metadata": {
            "compiled_at": datetime.now(timezone.utc).isoformat(),
            "total_advisories": total,
            "total_errors": errors,
            "source": "ossf/malicious-packages",
        },
        "index": index,
    }


def _normalize_ecosystem(ecosystem: str) -> str:
    """Normalize ecosystem names to match lockfile parser output."""
    mapping = {
        "npm": "npm",
        "pypi": "pypi",
        "crates.io": "crates",
        "go": "go",
        "maven": "maven",
        "nuget": "nuget",
        "rubygems": "rubygems",
    }
    return mapping.get(ecosystem, ecosystem)


def save_compiled_index(index: dict, output_path: Path | None = None) -> Path:
    """Write the compiled index to a single JSON file.

    Args:
        index: The index dict produced by :func:`compile_index`.
        output_path: Target file path.  Defaults to
            ``~/.gitsin/compiled_osv_index.json``.

    Returns:
        The path the index was written to.
    """
    output_path = Path(output_path) if output_path else DEFAULT_INDEX_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(index, f, separators=(",", ":"))  # Compact JSON.
    return output_path


def load_compiled_index(index_path: Path | None = None) -> dict | None:
    """Load the compiled index from disk.

    Returns ``None`` if the index file does not exist (Layer 2 silently
    skips in this case).
    """
    index_path = Path(index_path) if index_path else DEFAULT_INDEX_PATH
    if not index_path.is_file():
        return None
    try:
        with open(index_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Lockfile parsers — extract (name, version) tuples
# ---------------------------------------------------------------------------

def _parse_package_lock(path: Path) -> list[tuple[str, str]]:
    """Parse npm ``package-lock.json`` (v1, v2, v3 schemas).

    Returns a list of ``(package_name, version)`` tuples.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    results: list[tuple[str, str]] = []
    lock_version = data.get("lockfileVersion", 1)

    if lock_version >= 2 and "packages" in data:
        # v2/v3 — keys are "node_modules/pkg" or "node_modules/@scope/pkg".
        for key, info in data.get("packages", {}).items():
            if not key:  # Root package entry is "".
                continue
            # Extract package name from the key.
            name = key.rsplit("node_modules/", 1)[-1]
            version = info.get("version", "")
            if name:
                results.append((name, version))
    else:
        # v1 — flat dependencies dict.
        _walk_v1_deps(data.get("dependencies", {}), results)

    return results


def _walk_v1_deps(deps: dict, results: list[tuple[str, str]]) -> None:
    """Recursively walk v1 package-lock dependency tree."""
    for name, info in deps.items():
        version = info.get("version", "")
        results.append((name, version))
        # v1 nests transitive deps under "dependencies".
        if "dependencies" in info:
            _walk_v1_deps(info["dependencies"], results)


# Yarn lock patterns.
_YARN_PKG_RE = re.compile(
    r'^"?(@?[^@\s]+?)@'  # Captures scoped (@scope/name) or unscoped names.
)
_YARN_VERSION_RE = re.compile(
    r'^\s+version\s+"([^"]+)"'
)


def _parse_yarn_lock(path: Path) -> list[tuple[str, str]]:
    """Parse Yarn ``yarn.lock`` files.

    Handles scoped packages (``@scope/name``) and multi-resolution
    blocks (``lodash@^4.17.21, lodash@~4.17.0:``).

    Returns a list of ``(package_name, version)`` tuples.
    """
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    results: list[tuple[str, str]] = []
    current_name: str | None = None

    for line in content.splitlines():
        # Skip comments and empty lines.
        if not line or line.startswith("#"):
            continue

        # Package header line (not indented).
        if not line[0].isspace():
            m = _YARN_PKG_RE.match(line)
            current_name = m.group(1) if m else None
            continue

        # Version line (indented).
        if current_name is not None:
            m = _YARN_VERSION_RE.match(line)
            if m:
                results.append((current_name, m.group(1)))
                current_name = None  # Reset for next block.

    return results


def _parse_pipfile_lock(path: Path) -> list[tuple[str, str]]:
    """Parse Pipenv ``Pipfile.lock`` (JSON format).

    Extracts packages from both ``default`` and ``develop`` sections.
    Returns a list of ``(package_name, version)`` tuples.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    results: list[tuple[str, str]] = []
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            version = info.get("version", "").lstrip("=")
            results.append((name, version))
    return results


# PEP 508 package name: letters, digits, hyphens, underscores, dots.
_PIP_PKG_RE = re.compile(
    r'^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)'
)
# Version specifier operators.
_PIP_VERSION_SPLIT = re.compile(r'[><=!~]+')


def _parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """Parse pip ``requirements.txt`` files.

    Extracts package names per PEP 508.  Skips ``-r``, ``-e``,
    ``--index-url``, comments, and blank lines.

    Returns a list of ``(package_name, version)`` tuples.
    """
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    results: list[tuple[str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        # Skip comments, flags, blank lines.
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Skip environment markers after semicolons.
        line = line.split(";")[0].strip()

        m = _PIP_PKG_RE.match(line)
        if not m:
            continue

        name = m.group(1)
        rest = line[m.end():]

        # Extract first version specifier if present.
        version = ""
        parts = _PIP_VERSION_SPLIT.split(rest, maxsplit=1)
        if len(parts) > 1:
            version = parts[1].split(",")[0].strip()

        results.append((name, version))

    return results


# ---------------------------------------------------------------------------
# Lockfile discovery and cross-referencing
# ---------------------------------------------------------------------------

# Maps lockfile basename → (ecosystem, parser function).
_LOCKFILE_PARSERS: dict[str, tuple[str, callable]] = {
    "package-lock.json": ("npm", _parse_package_lock),
    "yarn.lock": ("npm", _parse_yarn_lock),
    "Pipfile.lock": ("pypi", _parse_pipfile_lock),
    "requirements.txt": ("pypi", _parse_requirements_txt),
}

# Directories to skip when searching for lockfiles.
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
}


def check_manifests(
    target_path: str,
    compiled_index: dict,
) -> List[ThreatIndicator]:
    """Scan lockfiles in the target repo against the compiled OSV index.

    Walks the target repository looking for known lockfile formats,
    parses each one to extract package names, and checks each name
    against the compiled index.

    Args:
        target_path: Root of the repository to scan.
        compiled_index: The full compiled index dict (with ``"index"``
            and ``"metadata"`` keys).

    Returns:
        A list of :class:`ThreatIndicator` for each dependency that
        matches a known-malicious package.
    """
    root = Path(target_path).resolve()
    if not root.exists():
        return []

    index = compiled_index.get("index", {})
    indicators: list[ThreatIndicator] = []

    for lockfile_path in _find_lockfiles(root):
        basename = lockfile_path.name
        if basename not in _LOCKFILE_PARSERS:
            continue

        ecosystem, parser = _LOCKFILE_PARSERS[basename]
        packages = parser(lockfile_path)
        rel_path = lockfile_path.relative_to(root).as_posix()

        ecosystem_index = index.get(ecosystem, {})

        for pkg_name, pkg_version in packages:
            # Normalize name for lookup (npm is case-sensitive,
            # PyPI normalises to lowercase with hyphens).
            lookup_name = pkg_name
            if ecosystem == "pypi":
                lookup_name = _normalize_pypi_name(pkg_name)

            advisories = ecosystem_index.get(lookup_name)
            if not advisories:
                continue

            # Found a match — build an indicator per advisory.
            for adv in advisories:
                indicators.append(ThreatIndicator(
                    rule_id=adv.get("id", "UNKNOWN"),
                    name=f"Known malicious {ecosystem} package: {pkg_name}",
                    category="malicious_dependency",
                    description=(
                        adv.get("summary", "")
                        or f"Package '{pkg_name}' is listed in the OpenSSF "
                           f"Malicious Packages database."
                    ),
                    file_path=rel_path,
                    matched_line=f"{pkg_name}@{pkg_version}" if pkg_version else pkg_name,
                    severity="CRITICAL",
                    confidence="high",
                    source="osv",
                    references=[
                        f"https://github.com/ossf/malicious-packages/blob/main/malicious/{ecosystem}/{pkg_name}"
                    ],
                ))

    return indicators


def _normalize_pypi_name(name: str) -> str:
    """Normalize a PyPI package name per PEP 503.

    Lowercases and replaces hyphens/underscores/dots with hyphens.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _find_lockfiles(root: Path):
    """Yield paths to known lockfile formats under *root*."""
    for child in root.iterdir():
        if child.is_dir():
            if child.name in _SKIP_DIRS:
                continue
            yield from _find_lockfiles(child)
        elif child.is_file() and child.name in _LOCKFILE_PARSERS:
            yield child
