<p align="center">
  <img src="assets/logo.png" alt="GitSin Logo" width="400"/>
</p>

# GitSin

**The Accountability Engine for Supply Chain & Cryptographic Security.**

GitSin is an automated compliance and accountability tool that weaponizes `git` metadata against insecure code. It wraps deterministic scanners, cross-references findings with the OpenSSF malicious package ledger, and uses `git blame` to permanently link vulnerabilities to the exact developers who committed them.

It translates terminal-level chaos into executive-level accountability.

---

## 👔 For Organizational Leaders (The "Why")

Cybersecurity is not a moat that should be gatekept by obscurity, black-box scanning SaaS dependencies, or post-deployment audits. Leaders need to know their risk, and they need to know who is responsible for it.

GitSin bridges the gap between engineering reality and executive oversight:
*   **Zero-Dependency & Air-Gapped:** Your code never leaves your machine. GitSin runs entirely locally, meaning zero data exfiltration risk and zero reliance on third-party cloud scanners.
*   **Financial Exposure Context:** A naked "Critical Risk" badge is unactionable FUD without context. GitSin calculates your repository's estimated financial exposure using the **IBM Cost of a Data Breach** baseline metrics for exposed infrastructure credentials.
*   **Compliance Aggregation:** Executive reporting automatically aggregates at-risk compliance frameworks (e.g., **SOC2 CC6.1, PCI-DSS Req 3, GDPR, SLSA Level 3**) so you instantly know your audit liabilities.
*   **The Executive Dashboard:** Run a single command and generate a standalone, beautifully rendered HTML file (< 50KB). Double-click it. View your repository's security state, compliance risks, and business impact visually. No login, no setup.

## 💻 For Security Engineers (The "How")

Engineers adopt tools because they are fast, deterministic, and easily integrated.

*   **Layer 1 - Cryptographic Heuristics:** GitSin uses `gitleaks` under the hood for highly optimized, regex-driven entropy detection to catch AWS keys, Stripe tokens, and RSA private keys.
*   **Layer 2 - The OSV Adapter:** It downloads the entire OpenSSF malicious package ledger, compiles 30,000+ shards of JSON into an O(1) memory index, and statically scans your lockfiles (`package-lock.json`, `yarn.lock`, `requirements.txt`, `Pipfile.lock`) for supply chain threats in milliseconds.
*   **Radical Accountability:** Findings are passed to our custom blame engine. We run `git blame --porcelain` to isolate the exact 40-character commit hash and author email of the engineer who introduced the vulnerability.
*   **Voyeur Protocol:** Automatically interrogates the local `git reflog` to identify who has cloned or interacted with the repository locally since the sin was committed.
*   **Pipeline Ready:** In addition to the C-suite HTML dashboard, GitSin exports natively to pure JSON and **SARIF v2.1.0** for seamless ingestion into GitHub Advanced Security or your CI/CD pipelines.

---

## 🚀 Getting Started

### Installation

GitSin is built in Python and managed via `uv` for lightning-fast dependency resolution.

```bash
# Clone the accountability engine
git clone https://github.com/your-org/gitsin.git
cd gitsin

# Install the dependencies
uv venv
uv pip install -e .
```

### Usage

**1. The Engineer's View (Terminal Rich Output)**
Run the scanner directly against any local repository to get a colored, interactive terminal table of all sins.
```bash
gitsin scan /path/to/your/repo
```

**2. The Executive View (Standalone HTML Dashboard)**
Generate a self-contained, XSS-immune HTML report designed for non-technical stakeholders.
```bash
gitsin scan /path/to/your/repo --output html > c-suite-report.html
```

**3. CI/CD Integration (SARIF Export)**
Export to the industry-standard SARIF format for automated PR blocking.
```bash
gitsin scan /path/to/your/repo --output sarif > results.sarif
```
