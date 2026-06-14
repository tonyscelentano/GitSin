# GEMINI.md - GitSin Architectural Instruction

Welcome. You are operating within the **GitSin** repository. GitSin is an automated compliance and accountability tool that wraps existing deterministic scanners (`gitleaks`), correlates findings with Git provenance data (`git blame`), maps violations to compliance frameworks, and detects voyeuristic clone activity (`git reflog`).

## 1. Project Philosophy & Core Mandates
Before writing code or refactoring within this project, adhere strictly to the following mandates:
- **Deterministic Over AI-Magic:** We use rule-based scanning, regex, and structured git metadata. Given the same repository state, the system *must* produce identical risk scores and blame records every single time.
- **Graceful Degradation (Offline-First):** The system must work entirely locally with zero external network access. Telemetry runs off local git logs. If a network feature is added later, it must gracefully fall back to local ops if disconnected.
- **Radical Accountability:** Security vulnerabilities are linked directly to individual commit signatures. The secrets have names.
- **Single Source of Truth:** `RiskLedger` (in `models.py`) is the immutable data contract. Everything flows into it, and exporters flow out of it.

## 2. Architecture & Module Map
The execution loop is synchronous and strictly isolated across the following modules:

*   **`gitsin/cli.py`**: The Typer orchestrator. It manages user input, instantiates the engines, and coordinates the execution loop. It handles the `Rich` terminal UI and routes machine-readable outputs to the `ExportManager`.
*   **`gitsin/models.py`**: The Pydantic data contracts. Strict schemas for `CommitActor`, `SinEvent`, `BlameRecord`, and the overarching `RiskLedger`.
*   **`gitsin/scanner.py` (`GitleaksOrchestrator`)**: Wraps the `gitleaks` binary via `subprocess`, dumps the JSON report, and deserializes it directly into `SinEvent` objects.
*   **`gitsin/blame.py` (`BlameEngine`)**: Executes `git blame --porcelain` on the exact lines reported by the scanner to isolate the 40-character commit hash and author metadata, instantiating `BlameRecord` objects.
*   **`gitsin/compliance.py` (`ComplianceEngine`)**: Handles the regulatory mapping matrix. Computes the deterministic 0-100 risk score and maps known Gitleaks rules (e.g., `aws-access-token`) to frameworks (e.g., `SOC2`, `PCI-DSS`).
*   **`gitsin/telemetry.py` (`TelemetryEngine`)**: The "Voyeur Protocol". Interrogates the local `git reflog` (falling back to `git log`) to identify who has cloned or interacted with the repository locally since the sin was committed.
*   **`gitsin/exporter.py` (`ExportManager`)**: Detaches the data from the UI. Serializes the `RiskLedger` into pure JSON or OASIS SARIF v2.1.0 specifications for downstream CI/CD ingestion.

## 3. Development Setup
To operate within this environment:
1.  **Environment Management**: The project relies on `uv`. Use `uv venv` and `uv pip install -e .`
2.  **Binary Dependencies**: The `gitleaks` binary must be available in the system PATH. The `Dockerfile` handles this automatically for production via an Alpine builder stage.
3.  **Testing**: Use `tests/fixture_generator.py` to programmatically seed a mock Git repository containing high-entropy target secrets. **Do not test live payloads directly in the source directory.**

## 4. Operational Directives
When modifying code:
- **No Async Complexity:** The tool is designed to run synchronously. Do not introduce `asyncio` loops unless fundamentally necessary and approved by the architect.
- **Pydantic Validation:** If adding new fields, they must be strongly typed in `models.py`.
- **Subprocess Safety:** Always use `capture_output=True`, set the `cwd` correctly, and handle `subprocess.CalledProcessError` gracefully without exposing raw stack traces to the user terminal.
- **Code Search (Sovereign Index):** This repository is indexed by Sovereign Index. DO NOT use bloated `ls` or text-based `grep` calls to navigate the codebase. ALWAYS use the `semantic_search` tool (provided via MCP) to find files and logic by intent before attempting deep reads.

You are now armed with the architectural context. Proceed with the reckoning.
