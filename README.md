# 🔍 AI License Risk Analyzer

```
  ╔══════════════════════════════════════════════════════╗
  ║   ██╗      █████╗     ██████╗  █████╗               ║
  ║   ██║     ██╔══██╗   ██╔════╝ ██╔══██╗              ║
  ║   ██║     ███████║   ██║      ███████║              ║
  ║   ██║     ██╔══██║   ██║      ██╔══██║              ║
  ║   ███████╗██║  ██║   ╚██████╗ ██║  ██║              ║
  ║   ╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝              ║
  ║                                                      ║
  ║       AI License Risk Analyzer  v1.0.0              ║
  ║   Scan dependencies. Classify risk. Stay safe.      ║
  ╚══════════════════════════════════════════════════════╝
```

> **Scan your Node.js dependencies for license risk, CVEs, and supply-chain indicators — then get a unified trust score with AI remediation tips.**

---

## 🚀 What Is This?

Open-source licenses are everywhere, but not all of them play nicely with commercial or proprietary software. One GPL dependency buried in your `node_modules` can legally require you to open-source your entire product.

**AI License Risk Analyzer** is a developer-first CLI tool that:

- Scans every dependency in any Node.js project
- Classifies each license as `SAFE`, `WARNING`, or `HIGH RISK`
- Checks known vulnerabilities via `npm audit`
- Runs supply-chain heuristics (typosquatting, OSV advisories, integrity checks)
- Computes an overall trust score (`0-100`) with per-package trust breakdown
- Optionally explains the risk in plain English via the **Gemini AI API**
- Presents everything in a beautifully formatted, color-coded terminal report

No configuration. No friction. Just run and know.

---

## ✨ Features

| Feature                           | Description                                                                    |
| --------------------------------- | ------------------------------------------------------------------------------ |
| 📦 **Dependency Scanning**        | Uses `license-checker` to scan all production dependencies                     |
| 🏷️ **License Classification**     | Rule-based engine classifies licenses into `SAFE / WARNING / HIGH RISK`        |
| 🔒 **Security Scan**              | Uses `npm audit` to detect known CVEs and severity breakdown                   |
| 🧬 **Supply-Chain Heuristics**    | Flags typosquat-like names, OSV alerts, and lockfile integrity issues          |
| 🛡️ **Unified Trust Dashboard**    | Produces overall trust score + lowest-trust package list                       |
| 🤖 **AI Explanations**            | Calls Google Gemini API to explain risky licenses in plain English (≤20 words) |
| 🛠️ **AI Remediation Suggestions** | Generates practical actions like replace/upgrade/pin/review for risky packages |
| 🎨 **Rich Terminal UI**           | ASCII banner, aligned table, color-coded output, progress steps                |
| 📊 **Summary Report**             | License + security + supply-chain + trust summaries with verdicts              |
| 🔧 **Multiple Output Modes**      | Default table, `--summary` compact view, `--json` for pipelines                |
| 🛡️ **Error Handling**             | Clear messages for missing paths, missing `package.json`, no `node_modules`    |
| 🔌 **Offline Fallback**           | Works without an API key — uses curated hardcoded explanations                 |

---

## 📦 Installation

### Clone and install

```bash
git clone https://github.com/your-username/ai-license-risk-analyzer.git
cd ai-license-risk-analyzer
npm install
```

### Run directly (no install)

```bash
node bin/index.js scan --path ./your-project
```

### Link globally (optional)

```bash
npm link
ai-license-risk-analyzer scan --path ./your-project
```

### Set your Gemini API key (optional — enables live AI explanations)

```bash
# Windows
set GEMINI_API_KEY=your_key_here

# macOS / Linux
export GEMINI_API_KEY=your_key_here
```

Get a free key at [aistudio.google.com](https://aistudio.google.com).

---

## 🛠️ Usage

### Basic scan

```bash
node bin/index.js scan
```

Scans the current directory. Shows per-package results + summary.

### Scan a specific project

```bash
node bin/index.js scan --path ./my-app
```

### Summary only

```bash
node bin/index.js scan --path ./my-app --summary
```

Shows only the risk count table — great for CI dashboards.

### With AI explanations

```bash
node bin/index.js scan --path ./my-app
```

AI explanations are on by default. Use `--no-ai` to disable.

### Security + supply-chain scan

```bash
node bin/index.js scan --path ./my-app --security --supply-chain
```

Runs CVE scan and supply-chain heuristics together, then prints a unified trust dashboard.

### JSON output

```bash
node bin/index.js scan --path ./my-app --json
```

Outputs structured JSON — pipe it to `jq`, save to a file, or feed into other tools.

```bash
node bin/index.js scan --json > report.json
```

### All options

```
Usage: ai-license-risk-analyzer scan [options]

Options:
  -p, --path <project-path>   Path to the project to scan (default: ".")
  --json                      Output results as raw JSON
  --summary                   Show only the risk count summary
  --no-ai                     Skip AI-generated explanations/remediation tips
  --explain-all               Explain all packages (including SAFE)
  --security                  Run npm audit for known CVEs
  --supply-chain              Run typosquat/OSV/integrity heuristics
  -h, --help                  Display help
```

---

## 📋 Sample Output

### Default scan

```
  ╔══════════════════════════════════════════════════════╗
  ║       AI License Risk Analyzer  v1.0.0              ║
  ║   Scan dependencies. Classify risk. Stay safe.      ║
  ╚══════════════════════════════════════════════════════╝

  Project  ./my-app
  Time     4/16/2026, 9:30:41 AM

  ⏳  Scanning licenses ... ✔  42 packages found
  ⚙️   Classifying risks  ... ✔  done

      Package              Version   License        Risk
  ─────────────────────────────────────────────────────────
  ✖  some-old-lib         2.1.0     GPL-3.0        HIGH RISK
  ⚠  weak-copyleft-pkg    1.0.0     LGPL-2.1       WARNING

  ✔  lodash               4.17.21   MIT            SAFE
  ✔  axios                1.6.0     MIT            SAFE
  ✔  chalk                5.3.0     MIT            SAFE
  ─────────────────────────────────────────────────────────

  Results Summary
  ────────────────────────────────────────
  ✔   Safe          39   ███████████████░
  ⚠   Warning        2   ░░░░░░░░░░░░░░░░
  ✖   High Risk      1   ░░░░░░░░░░░░░░░░
  ────────────────────────────────────────
  Total          42

  ✖  1 high-risk license(s) detected. Review before shipping.
```

### With `--ai` flag

```
  ✖  some-old-lib         2.1.0     GPL-3.0        HIGH RISK
       ↳ Strong copyleft. All derivatives must be GPL. Incompatible with closed-source.

  ⚠  weak-copyleft-pkg   1.0.0     LGPL-2.1       WARNING
       ↳ Weak copyleft. Safe if used as a library. Modifications to the lib must be open.
```

### With `--summary`

```
  Results Summary
  ────────────────────────────────────────
  ✔   Safe          39   ███████████████░
  ⚠   Warning        2   ░░░░░░░░░░░░░░░░
  ✖   High Risk      1   ░░░░░░░░░░░░░░░░
  ────────────────────────────────────────
  Total          42

  ✖  1 high-risk license(s) detected. Review before shipping.
```

---

## 🏗️ Project Structure

```
ai-license-risk-analyzer/
├── bin/
│   └── index.js          # CLI entry point (#!/usr/bin/env node)
├── src/
│   ├── cli.js            # Commander commands, output formatting
│   ├── scanner.js        # license-checker wrapper, structured output
│   ├── riskAnalyzer.js   # classifyLicense() + analyzeRisks()
│   ├── aiExplainer.js    # getAIExplanation() via Gemini API + fallbacks
│   ├── securityScanner.js   # npm audit parser + vulnerability normalization
│   ├── supplyChainScanner.js # typosquat/OSV/integrity heuristic scanner
│   └── utils.js          # Shared display helpers
└── package.json          # ES modules, bin entry, dependencies
```

---

## 🧠 How Risk Classification Works

The engine uses a **keyword rule table** evaluated in priority order:

| Risk           | Matched Licenses                                            | Why it matters                                    |
| -------------- | ----------------------------------------------------------- | ------------------------------------------------- |
| 🔴 `HIGH RISK` | `GPL-1/2/3`, `AGPL-1/3`                                     | Strong copyleft — forces your product open-source |
| 🟡 `WARNING`   | `LGPL-*`, `MPL-2.0`, `EPL-*`, `EUPL`, `Unknown`             | Weak copyleft or unknown — review before shipping |
| 🟢 `SAFE`      | `MIT`, `ISC`, `Apache-2.0`, `BSD-*`, `CC0-1.0`, `Unlicense` | Permissive — no significant restrictions          |

> LGPL keywords are evaluated **before** GPL to prevent substring false-matches (`LGPL-3.0` containing `GPL-3.0`).

---

## 📡 AI Integration

When `--ai` is passed, the tool calls [Google Gemini](https://aistudio.google.com) with this prompt:

> _"Explain the {license} software license in exactly 2 simple lines for developers. Include the risk level. Keep total response under 20 words."_

**Without a key?** The tool falls back to curated offline explanations for 15+ common licenses — no internet required.

---

## 🔮 Future Improvements

- [ ] **HTML / PDF report export** — shareable audit reports for teams
- [ ] **CI/CD integration** — exit code `1` on `HIGH RISK`, GitHub Actions ready
- [ ] **Config file support** — `.licenserc` to whitelist specific packages
- [ ] **Transitive dependency scanning** — analyze indirect deps, not just direct
- [ ] **License compatibility matrix** — flag incompatible license combinations
- [ ] **Auto-fix suggestions** — recommend safer alternative packages
- [ ] **Dashboard UI** — browser-based visual report with drill-down
- [ ] **SBOM export** — Software Bill of Materials in SPDX / CycloneDX format

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push and open a PR

---

## 📄 License

MIT © 2026 — Free to use, modify, and ship.

---

<p align="center">
  Built with ❤️ for developers who care about their supply chain.
</p>
