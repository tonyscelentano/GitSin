"""
Tests for gitsin.osv_adapter — Layer 2 hydrated threat intelligence.

Tests the compiled index builder, all four lockfile parsers, the manifest
cross-referencing logic, and the PyPI name normalisation.  All tests are
fully offline — no network, no git subprocess calls.
"""

import json
import pytest
from pathlib import Path

from gitsin.osv_adapter import (
    compile_index,
    save_compiled_index,
    load_compiled_index,
    check_manifests,
    _parse_package_lock,
    _parse_yarn_lock,
    _parse_pipfile_lock,
    _parse_requirements_txt,
    _normalize_pypi_name,
)
from gitsin.models import ThreatIndicator


# ── Helpers — create fixture files ────────────────────────────────

def _make_osv_json(directory: Path, advisory_id: str, ecosystem: str, name: str, summary: str = ""):
    """Write a minimal OSV JSON file into a directory structure."""
    pkg_dir = directory / "malicious" / ecosystem / name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    osv = {
        "id": advisory_id,
        "summary": summary or f"Malicious package: {name}",
        "affected": [
            {
                "package": {
                    "ecosystem": ecosystem,
                    "name": name,
                },
            }
        ],
    }
    (pkg_dir / f"{advisory_id}.json").write_text(json.dumps(osv))


# ── compile_index ─────────────────────────────────────────────────

class TestCompileIndex:
    def test_empty_directory(self, tmp_path: Path):
        index = compile_index(tmp_path)
        assert index["metadata"]["total_advisories"] == 0
        assert index["index"] == {}

    def test_single_advisory(self, tmp_path: Path):
        _make_osv_json(tmp_path, "MAL-2024-001", "npm", "bad-pkg", "Test advisory")
        index = compile_index(tmp_path)

        assert index["metadata"]["total_advisories"] == 1
        assert "npm" in index["index"]
        assert "bad-pkg" in index["index"]["npm"]
        assert index["index"]["npm"]["bad-pkg"][0]["id"] == "MAL-2024-001"

    def test_multiple_ecosystems(self, tmp_path: Path):
        _make_osv_json(tmp_path, "MAL-2024-001", "npm", "bad-npm-pkg")
        _make_osv_json(tmp_path, "MAL-2024-002", "PyPI", "bad-pypi-pkg")
        index = compile_index(tmp_path)

        assert index["metadata"]["total_advisories"] == 2
        assert "npm" in index["index"]
        assert "pypi" in index["index"]

    def test_multiple_advisories_same_package(self, tmp_path: Path):
        _make_osv_json(tmp_path, "MAL-2024-001", "npm", "event-stream", "First report")
        # Write second advisory to same package dir.
        pkg_dir = tmp_path / "malicious" / "npm" / "event-stream"
        osv2 = {
            "id": "MAL-2024-002",
            "summary": "Second report",
            "affected": [{"package": {"ecosystem": "npm", "name": "event-stream"}}],
        }
        (pkg_dir / "MAL-2024-002.json").write_text(json.dumps(osv2))

        index = compile_index(tmp_path)
        assert len(index["index"]["npm"]["event-stream"]) == 2

    def test_malformed_json_counted_as_error(self, tmp_path: Path):
        pkg_dir = tmp_path / "malicious" / "npm" / "bad"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "broken.json").write_text("{not valid json")

        index = compile_index(tmp_path)
        assert index["metadata"]["total_errors"] == 1
        assert index["metadata"]["total_advisories"] == 0

    def test_ecosystem_normalization(self, tmp_path: Path):
        _make_osv_json(tmp_path, "MAL-001", "PyPI", "pkg-a")
        _make_osv_json(tmp_path, "MAL-002", "crates.io", "pkg-b")
        index = compile_index(tmp_path)

        # PyPI → pypi, crates.io → crates
        assert "pypi" in index["index"]
        assert "crates" in index["index"]

    def test_summary_truncation(self, tmp_path: Path):
        long_summary = "A" * 500
        _make_osv_json(tmp_path, "MAL-001", "npm", "pkg", long_summary)
        index = compile_index(tmp_path)

        stored_summary = index["index"]["npm"]["pkg"][0]["summary"]
        assert len(stored_summary) == 200


# ── save / load compiled index ────────────────────────────────────

class TestIndexPersistence:
    def test_round_trip(self, tmp_path: Path):
        index = {
            "metadata": {"compiled_at": "2024-01-01", "total_advisories": 1, "source": "test"},
            "index": {"npm": {"pkg": [{"id": "MAL-001", "summary": "test"}]}},
        }
        out = tmp_path / "index.json"
        save_compiled_index(index, out)
        loaded = load_compiled_index(out)

        assert loaded is not None
        assert loaded["metadata"]["total_advisories"] == 1
        assert loaded["index"]["npm"]["pkg"][0]["id"] == "MAL-001"

    def test_load_nonexistent_returns_none(self):
        result = load_compiled_index(Path("/nonexistent/path/index.json"))
        assert result is None

    def test_load_corrupt_returns_none(self, tmp_path: Path):
        corrupt = tmp_path / "index.json"
        corrupt.write_text("{broken json")
        assert load_compiled_index(corrupt) is None

    def test_compact_json_output(self, tmp_path: Path):
        index = {"metadata": {}, "index": {"npm": {"pkg": []}}}
        out = tmp_path / "index.json"
        save_compiled_index(index, out)
        content = out.read_text()
        # Compact JSON — no spaces after separators.
        assert " " not in content or content.count(" ") < 5


# ── Lockfile parsers ──────────────────────────────────────────────

class TestParsePackageLock:
    def test_v3_schema(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/@babel/core": {"version": "7.24.0"},
            },
        }))
        result = _parse_package_lock(lock)
        names = [r[0] for r in result]
        assert "lodash" in names
        assert "@babel/core" in names
        assert len(result) == 2  # Root package excluded.

    def test_v1_schema(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "express": {"version": "4.18.2"},
                "debug": {
                    "version": "4.3.4",
                    "dependencies": {
                        "ms": {"version": "2.1.2"},
                    },
                },
            },
        }))
        result = _parse_package_lock(lock)
        names = [r[0] for r in result]
        assert "express" in names
        assert "debug" in names
        assert "ms" in names  # Transitive dependency.

    def test_empty_file(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text("{}")
        assert _parse_package_lock(lock) == []

    def test_corrupt_file(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text("not json")
        assert _parse_package_lock(lock) == []


class TestParseYarnLock:
    def test_basic_packages(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '# yarn lockfile v1\n'
            '\n'
            'lodash@^4.17.21:\n'
            '  version "4.17.21"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n'
            '\n'
            'express@^4.18.0:\n'
            '  version "4.18.2"\n'
            '  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"\n'
        )
        result = _parse_yarn_lock(lock)
        assert ("lodash", "4.17.21") in result
        assert ("express", "4.18.2") in result

    def test_scoped_package(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '"@babel/core@^7.0.0":\n'
            '  version "7.24.0"\n'
        )
        result = _parse_yarn_lock(lock)
        assert ("@babel/core", "7.24.0") in result

    def test_multi_resolution_block(self, tmp_path: Path):
        """Yarn multi-resolution: lodash@^4.17.21, lodash@~4.17.0:"""
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            'lodash@^4.17.21, lodash@~4.17.0:\n'
            '  version "4.17.21"\n'
        )
        result = _parse_yarn_lock(lock)
        # Should extract "lodash" (first name before @).
        assert result[0][0] == "lodash"
        assert result[0][1] == "4.17.21"

    def test_empty_file(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_text("")
        assert _parse_yarn_lock(lock) == []


class TestParsePipfileLock:
    def test_default_and_develop(self, tmp_path: Path):
        lock = tmp_path / "Pipfile.lock"
        lock.write_text(json.dumps({
            "default": {
                "flask": {"version": "==2.3.2"},
                "click": {"version": "==8.1.7"},
            },
            "develop": {
                "pytest": {"version": "==8.2.0"},
            },
        }))
        result = _parse_pipfile_lock(lock)
        names = [r[0] for r in result]
        assert "flask" in names
        assert "click" in names
        assert "pytest" in names
        # Version should have == stripped.
        flask_version = [r[1] for r in result if r[0] == "flask"][0]
        assert flask_version == "2.3.2"

    def test_empty_sections(self, tmp_path: Path):
        lock = tmp_path / "Pipfile.lock"
        lock.write_text(json.dumps({"default": {}, "develop": {}}))
        assert _parse_pipfile_lock(lock) == []


class TestParseRequirementsTxt:
    def test_pinned_versions(self, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.2\nrequests>=2.28.0\n")
        result = _parse_requirements_txt(req)
        names = [r[0] for r in result]
        assert "flask" in names
        assert "requests" in names

    def test_bare_names(self, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("numpy\npandas\n")
        result = _parse_requirements_txt(req)
        assert ("numpy", "") in result
        assert ("pandas", "") in result

    def test_comments_and_flags_skipped(self, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text(
            "# This is a comment\n"
            "-r other.txt\n"
            "-e git+https://github.com/user/repo.git\n"
            "--index-url https://pypi.org/simple/\n"
            "flask==2.0.0\n"
            "\n"
        )
        result = _parse_requirements_txt(req)
        assert len(result) == 1
        assert result[0][0] == "flask"

    def test_environment_markers_stripped(self, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text('pywin32>=300; sys_platform == "win32"\n')
        result = _parse_requirements_txt(req)
        assert result[0][0] == "pywin32"


# ── PyPI name normalisation ──────────────────────────────────────

class TestNormalizePypiName:
    def test_lowercase(self):
        assert _normalize_pypi_name("Flask") == "flask"

    def test_underscores_to_hyphens(self):
        assert _normalize_pypi_name("my_package") == "my-package"

    def test_dots_to_hyphens(self):
        assert _normalize_pypi_name("zope.interface") == "zope-interface"

    def test_mixed(self):
        assert _normalize_pypi_name("My_Package.Name") == "my-package-name"

    def test_already_normalized(self):
        assert _normalize_pypi_name("flask") == "flask"


# ── check_manifests (end-to-end) ─────────────────────────────────

class TestCheckManifests:
    @pytest.fixture
    def compiled_index(self):
        """A minimal compiled index with known-bad packages."""
        return {
            "metadata": {"total_advisories": 3},
            "index": {
                "npm": {
                    "event-stream": [
                        {"id": "MAL-2024-001", "summary": "Compromised npm package"},
                    ],
                    "flatmap-stream": [
                        {"id": "MAL-2024-002", "summary": "Malicious dependency"},
                    ],
                },
                "pypi": {
                    "colourama": [
                        {"id": "MAL-2024-003", "summary": "Typosquat of colorama"},
                    ],
                },
            },
        }

    def test_npm_match_via_package_lock(self, tmp_path: Path, compiled_index):
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/event-stream": {"version": "3.3.6"},
            },
        }))

        results = check_manifests(str(tmp_path), compiled_index)
        assert len(results) == 1
        assert results[0].rule_id == "MAL-2024-001"
        assert results[0].source == "osv"
        assert results[0].category == "malicious_dependency"
        assert results[0].severity == "CRITICAL"

    def test_pypi_match_via_requirements(self, tmp_path: Path, compiled_index):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.2\ncolourama==0.4.6\n")

        results = check_manifests(str(tmp_path), compiled_index)
        assert len(results) == 1
        assert results[0].rule_id == "MAL-2024-003"
        assert "colourama" in results[0].matched_line

    def test_pypi_normalization_match(self, tmp_path: Path, compiled_index):
        """PyPI names with underscores/dots should still match."""
        # The index has "colourama" — test that "Colourama" also matches.
        req = tmp_path / "requirements.txt"
        req.write_text("Colourama==0.4.6\n")

        results = check_manifests(str(tmp_path), compiled_index)
        assert len(results) == 1

    def test_no_match_clean_repo(self, tmp_path: Path, compiled_index):
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }))

        results = check_manifests(str(tmp_path), compiled_index)
        assert results == []

    def test_no_lockfiles(self, tmp_path: Path, compiled_index):
        (tmp_path / "README.md").write_text("# Clean project")
        results = check_manifests(str(tmp_path), compiled_index)
        assert results == []

    def test_empty_index(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/lodash": {"version": "4.17.21"}},
        }))
        empty_index = {"metadata": {}, "index": {}}
        results = check_manifests(str(tmp_path), empty_index)
        assert results == []

    def test_result_types(self, tmp_path: Path, compiled_index):
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/event-stream": {"version": "3.3.6"},
                "node_modules/flatmap-stream": {"version": "0.1.1"},
            },
        }))

        results = check_manifests(str(tmp_path), compiled_index)
        assert len(results) == 2
        for r in results:
            assert isinstance(r, ThreatIndicator)
            assert r.confidence == "high"
            assert r.source == "osv"
