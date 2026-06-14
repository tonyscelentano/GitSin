# GitSin Usage Guide

GitSin is designed to be a zero-dependency, locally-executed accountability engine. It requires no cloud connection and never uploads your source code. 

You can run GitSin either via the standalone executable (`gitsin.exe`) or directly from the source using `uv`.

## 🚀 The Basics

The core command is `scan`, which requires a single argument: the path to the local git repository you want to audit.

**Using the Standalone Executable:**
```bash
# Scan a repository in the current directory
.\gitsin.exe scan .

# Scan a specific repository path
.\gitsin.exe scan C:\Dev\MyProject
```

**Using Python / Source (Requires `uv`):**
```bash
uv run gitsin scan C:\Dev\MyProject
```

---

## 👔 "Suits Mode" (Financial Exposure Theater)

By default, GitSin operates as an engineering tool, outputting deterministic risk scores (0-100). However, if you are generating reports for C-Suite executives or leadership, you can enable **Suits Mode**.

Suits Mode calculates a projected "Compliance Exposure Blast Radius" based on the IBM Cost of a Data Breach report metrics. It attaches a massive dollar-amount penalty to every leaked credential to translate engineering risk into business risk.

**To enable Suits Mode, append the `--suits-mode` flag:**
```bash
.\gitsin.exe scan C:\Dev\MyProject --suits-mode
```
*Note: This flag affects both terminal output and HTML report generation.*

---

## 📊 Exporting Reports

GitSin supports three output modes via the `--output` (or `-o`) flag.

### 1. Terminal (Default)
Outputs an interactive, color-coded Rich table directly in your terminal. Best for engineers running local audits.
```bash
.\gitsin.exe scan C:\Dev\MyProject
```

### 2. The Executive Dashboard (HTML)
Generates a standalone, XSS-immune HTML file (< 50KB) that contains no external dependencies. You can double-click this file to view a beautiful, C-Suite ready dashboard containing gauge charts, compliance framework mapping, and the Git "Voyeur Protocol" telemetry logs.

```bash
.\gitsin.exe scan C:\Dev\MyProject --suits-mode --output html > c-suite-report.html
```

### 3. Pipeline Integration (SARIF)
Exports findings to the industry-standard SARIF (Static Analysis Results Interchange Format) v2.1.0 specification. This is used for uploading results to GitHub Advanced Security or failing CI/CD pipeline builds.

```bash
.\gitsin.exe scan C:\Dev\MyProject --output sarif > results.sarif
```

---

## ⚙️ Advanced Flags

*   `--no-threat-scan`: By default, GitSin runs Layer 1 heuristic supply chain threat detection (looking for malicious build scripts, base64 payloads). Pass this flag to disable the heuristics and *only* scan for cryptographic secrets.
    ```bash
    .\gitsin.exe scan C:\Dev\MyProject --no-threat-scan
    ```
