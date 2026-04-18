import "dotenv/config";
import { Command } from "commander";
import chalk from "chalk";
import fs from "fs";
import path from "path";
import { resolveProjectRoot, scanLicenses } from "./scanner.js";
import { classifyLicense } from "./riskAnalyzer.js";
import {
  getAIExplanation,
  getRemediationSuggestion,
  hasApiKey,
} from "./aiExplainer.js";
import { runSecurityScan, SEV_ICON } from "./securityScanner.js";
import { runSupplyChainScan } from "./supplyChainScanner.js";

// ─── Risk display maps ────────────────────────────────────────────────────────

const ICON = {
  SAFE: chalk.green("✔"),
  WARNING: chalk.yellow("⚠"),
  HIGH_RISK: chalk.red("✖"),
};

const LABEL = {
  SAFE: chalk.green.bold("SAFE     "),
  WARNING: chalk.yellow.bold("WARNING  "),
  HIGH_RISK: chalk.red.bold("HIGH RISK"),
};

const RISK_COLOR = {
  SAFE: chalk.green,
  WARNING: chalk.yellow,
  HIGH_RISK: chalk.red,
};

const SEV_COLOR = {
  critical: chalk.red.bold,
  high: chalk.red,
  moderate: chalk.yellow,
  low: chalk.green,
  info: chalk.gray,
};

const SUPPLY_SEV_COLOR = {
  high: chalk.red,
  moderate: chalk.yellow,
  low: chalk.cyan,
};

const SUPPLY_SEV_ICON = {
  high: "🚨",
  moderate: "⚠",
  low: "ℹ",
};

const ORANGE = chalk.hex("#d97706");

// ─── Program ──────────────────────────────────────────────────────────────────

const program = new Command();

program
  .name("ai-license-risk-analyzer")
  .description(
    "Scan license, CVE, and supply-chain risks across your project dependencies",
  )
  .version("1.0.0");

// ─── configure command ────────────────────────────────────────────────────────

program
  .command("configure")
  .description("Save your Google AI Studio API key for AI-powered explanations")
  .option("-k, --key <api-key>", "Your Gemini API key from Google AI Studio")
  .action((options) => {
    const envPath = path.resolve(".env");

    if (!options.key) {
      console.log();
      console.log(chalk.cyan.bold("  ⚙  Configure Gemini API Key"));
      console.log(
        chalk.gray("  ─────────────────────────────────────────────────"),
      );
      console.log(
        chalk.white("  Get your free API key at: ") +
          chalk.cyan.underline("https://aistudio.google.com/apikey"),
      );
      console.log();
      console.log(chalk.yellow("  Usage:"));
      console.log(
        chalk.gray("    node bin/index.js configure --key YOUR_API_KEY"),
      );
      console.log();
      if (hasApiKey()) {
        console.log(
          chalk.green(
            "  ✔  API key is already configured. Gemini AI is live.\n",
          ),
        );
      } else {
        console.log(
          chalk.red(
            "  ✖  No API key found. AI explanations will use built-in knowledge base.\n",
          ),
        );
      }
      return;
    }

    let envContent = "";
    if (fs.existsSync(envPath)) {
      envContent = fs.readFileSync(envPath, "utf8");
      envContent = envContent.replace(/^GEMINI_API_KEY=.*\n?/m, "");
    }
    envContent = `GEMINI_API_KEY=${options.key}\n` + envContent;
    fs.writeFileSync(envPath, envContent, "utf8");

    console.log();
    console.log(chalk.green.bold("  ✔  API key saved to .env"));
    console.log(
      chalk.gray(
        "     Run your next scan — Gemini AI will explain every license in plain English.\n",
      ),
    );
  });

// ─── scan command ─────────────────────────────────────────────────────────────

program
  .command("scan")
  .description(
    "Scan a project directory for license risks, known CVEs, and supply-chain heuristics",
  )
  .option(
    "-p, --path <project-path>",
    "Path to the project directory (or package.json file) to scan",
    ".",
  )
  .option("--json", "Output results as raw JSON")
  .option("--summary", "Show only the risk count summary")
  .option("--no-ai", "Skip AI license explanations")
  .option(
    "--explain-all",
    "Show AI explanations for ALL packages including SAFE ones",
  )
  .option(
    "--security",
    "Run npm audit and show known CVEs / vulnerabilities inline",
  )
  .option(
    "--supply-chain",
    "Run supply-chain heuristics (typosquatting, OSV, integrity checks)",
  )
  .action(async (options) => {
    const {
      path: projectPath,
      json: asJson,
      summary: summaryOnly,
      ai: withAI,
      explainAll,
      security: withSecurity,
      supplyChain: withSupplyChain,
    } = options;

    // Current product behavior: enabling security also enables supply scan
    // to provide a combined risk/trust perspective in one run.
    const withSupply = withSecurity || withSupplyChain;

    try {
      const projectRoot = resolveProjectRoot(projectPath);
      const displayProjectPath = formatProjectDisplayPath(projectRoot);

      if (!asJson) printBanner(displayProjectPath, withSecurity, withSupply);

      // ── Step 1: License scan ────────────────────────────────────────────────
      if (!asJson)
        process.stdout.write(chalk.gray("  📦  Scanning licenses        ..."));
      const packages = await scanLicenses(projectRoot);
      if (!asJson)
        console.log(
          chalk.green(" ✔") + chalk.gray(`  ${packages.length} packages found`),
        );

      // ── Step 2: Classify ────────────────────────────────────────────────────
      if (!asJson)
        process.stdout.write(chalk.gray("  ⚙️   Classifying risks        ..."));
      const classified = packages.map((pkg) => ({
        ...pkg,
        ...classifyLicense(pkg.license),
        vulns: [], // filled in by security scan
        supplySignals: [], // filled in by supply-chain scan
        trustScore: 100,
        remediation: null,
        isTransitive: false, // only transitive-vuln rows are true
      }));
      if (!asJson) console.log(chalk.green(" ✔") + chalk.gray("  done"));

      // ── Step 3: Security scan (npm audit) ───────────────────────────────────
      let secSummary = null;
      // Synthetic rows for vulnerable packages that do not appear in the
      // license scan list (usually transitive-only dependencies).
      let transitiveRows = [];
      let supplySummary = null;

      if (withSecurity) {
        if (!asJson)
          process.stdout.write(
            chalk.gray("  🔒  Running security scan    ..."),
          );
        try {
          const { vulnsByPackage, summary } =
            await runSecurityScan(projectRoot);
          secSummary = summary;

          // Attach vulns to matching packages in license list
          const classifiedNames = new Set(classified.map((p) => p.name));
          for (const pkg of classified) {
            if (vulnsByPackage.has(pkg.name)) {
              pkg.vulns = vulnsByPackage.get(pkg.name);
            }
          }

          // Build synthetic rows for transitive-only vulnerable packages
          for (const [name, vulns] of vulnsByPackage) {
            if (!classifiedNames.has(name)) {
              // Determine worst severity for risk label
              const worstSev = vulns[0]?.severity || "moderate";
              const risk =
                worstSev === "critical" || worstSev === "high"
                  ? "HIGH_RISK"
                  : "WARNING";

              transitiveRows.push({
                name,
                version: "(transitive)",
                license: "N/A",
                risk,
                message: "Transitive dependency with known vulnerabilities",
                vulns,
                supplySignals: [],
                trustScore: 100,
                remediation: null,
                isTransitive: true,
              });
            }
          }

          const vulnCount = secSummary.total ?? 0;
          if (!asJson) {
            if (vulnCount === 0) {
              console.log(
                chalk.green(" ✔") + chalk.gray("  no known vulnerabilities"),
              );
            } else {
              const critHigh =
                (secSummary.critical || 0) + (secSummary.high || 0);
              const badge =
                critHigh > 0
                  ? chalk.red.bold(` ${vulnCount} found`)
                  : chalk.yellow(` ${vulnCount} found`);
              console.log(chalk.green(" ✔") + badge);
            }
          }
        } catch (err) {
          if (!asJson)
            console.log(
              chalk.yellow(" ⚠") + chalk.gray(`  skipped — ${err.message}`),
            );
        }
      }

      // ── Step 4: Supply-chain scan ──────────────────────────────────────────
      if (withSupply) {
        if (!asJson)
          process.stdout.write(
            chalk.gray("  🧬  Running supply-chain scan..."),
          );

        try {
          const { signalsByPackage, summary } = await runSupplyChainScan(
            projectRoot,
            classified,
          );
          supplySummary = summary;

          for (const pkg of classified) {
            pkg.supplySignals = signalsByPackage[buildPkgKey(pkg)] || [];
          }

          const signalCount = supplySummary.totalSignals || 0;
          if (!asJson) {
            if (signalCount === 0) {
              console.log(
                chalk.green(" ✔") + chalk.gray("  no supply-chain indicators"),
              );
            } else {
              const highCount = supplySummary.high || 0;
              const badge =
                highCount > 0
                  ? chalk.red.bold(` ${signalCount} indicator(s)`)
                  : chalk.yellow(` ${signalCount} indicator(s)`);
              console.log(chalk.green(" ✔") + badge);
            }
          }

          if (!asJson && supplySummary.warnings?.length) {
            for (const warn of supplySummary.warnings) {
              console.log(chalk.yellow("  ⚠  ") + chalk.gray(warn));
            }
          }
        } catch (err) {
          if (!asJson)
            console.log(
              chalk.yellow(" ⚠") + chalk.gray(`  skipped — ${err.message}`),
            );
        }
      }

      // ── Step 5: AI license explanations ─────────────────────────────────────
      // Explain risky/flagged packages by default; safe clean packages are
      // included only when --explain-all is explicitly requested.
      const toExplain = withAI
        ? classified.filter(
            (p) =>
              explainAll ||
              p.risk !== "SAFE" ||
              p.vulns.length > 0 ||
              p.supplySignals.length > 0,
          )
        : [];

      if (withAI && !asJson && toExplain.length > 0) {
        const source = hasApiKey() ? "Gemini AI" : "built-in knowledge";
        process.stdout.write(chalk.gray(`  🤖  Generating explanations  ...`));
        for (const pkg of toExplain) {
          pkg.aiExplanation = await getAIExplanation(pkg.license, pkg.risk);
        }
        console.log(
          chalk.green(" ✔") +
            chalk.gray(
              `  ${toExplain.length} licenses explained via ${source}`,
            ),
        );
      }

      // ── Step 6: Trust score and remediation suggestions ────────────────────
      const licenseSummary = buildLicenseSummary(classified);
      // This call pre-populates mutable trustScore fields used for ordering
      // remediation targets below.
      buildTrustDashboard(
        classified,
        transitiveRows,
        secSummary,
        supplySummary,
      );

      const remediationTargets = pickRemediationTargets(
        classified,
        transitiveRows,
      );
      if (withAI && remediationTargets.length > 0) {
        if (!asJson)
          process.stdout.write(
            chalk.gray("  🛠️   Generating remediation   ..."),
          );

        for (const pkg of remediationTargets) {
          pkg.remediation = await getRemediationSuggestion({
            name: pkg.name,
            license: pkg.license,
            risk: pkg.risk,
            vulns: pkg.vulns || [],
            supplySignals: pkg.supplySignals || [],
          });
        }

        if (!asJson)
          console.log(
            chalk.green(" ✔") +
              chalk.gray(
                `  ${remediationTargets.length} package suggestion(s)`,
              ),
          );
      }

      const trustDashboard = buildTrustDashboard(
        classified,
        transitiveRows,
        secSummary,
        supplySummary,
      );

      // Info tips
      if (!asJson) {
        if (withAI && !hasApiKey()) {
          console.log(
            chalk.gray("  💡  Tip: Run ") +
              chalk.cyan("node bin/index.js configure --key YOUR_KEY") +
              chalk.gray(" to unlock live Gemini AI explanations."),
          );
        }
        if (withAI && !explainAll) {
          const skipped = classified.filter(
            (p) =>
              p.risk === "SAFE" && !p.vulns?.length && !p.supplySignals?.length,
          ).length;
          if (skipped > 0) {
            console.log(
              chalk.gray(`  💡  ${skipped} safe packages skipped. Add `) +
                chalk.cyan("--explain-all") +
                chalk.gray(" to explain every license."),
            );
          }
        }
        if (!withSecurity && !withSupplyChain) {
          console.log(
            chalk.gray("  💡  Add ") +
              chalk.cyan("--security") +
              chalk.gray(" for CVEs and ") +
              chalk.cyan("--supply-chain") +
              chalk.gray(" for typosquat/OSV/integrity heuristics."),
          );
        }
        console.log();
      }

      // ── Step 7: Output ──────────────────────────────────────────────────────
      // JSON mode is designed for CI/pipelines; terminal UI is skipped.
      if (asJson) {
        console.log(
          JSON.stringify(
            {
              summary: licenseSummary,
              security: secSummary,
              supplyChain: supplySummary,
              trust: trustDashboard,
              packages: classified,
              transitive: transitiveRows,
            },
            null,
            2,
          ),
        );
        return;
      }

      // Summary mode keeps high-level dashboards only.
      if (summaryOnly) {
        printLicenseSummaryBox(licenseSummary);
        if (secSummary) printSecuritySummaryBox(secSummary);
        if (supplySummary) printSupplyChainSummaryBox(supplySummary);
        printTrustDashboard(trustDashboard);
        return;
      }

      printPackageTable(classified, transitiveRows);
      printLicenseSummaryBox(licenseSummary);
      if (secSummary) printSecuritySummaryBox(secSummary);
      if (supplySummary) printSupplyChainSummaryBox(supplySummary);
      printTrustDashboard(trustDashboard);
    } catch (err) {
      console.error(chalk.red(`\n  ✖  ${err.message}\n`));
      process.exit(1);
    }
  });

// ─── Help text ────────────────────────────────────────────────────────────────

program.addHelpText(
  "after",
  `
${chalk.bold("Examples:")}
  $ ai-license-risk-analyzer scan
  $ ai-license-risk-analyzer scan --path ./my-project
  $ ai-license-risk-analyzer scan --path ./my-project/package.json
  $ ai-license-risk-analyzer scan --path ./my-project --security
  $ ai-license-risk-analyzer scan --path ./my-project --supply-chain
  $ ai-license-risk-analyzer scan --path ./my-project --security --explain-all
  $ ai-license-risk-analyzer scan --path ./my-project --security --supply-chain
  $ ai-license-risk-analyzer scan --path ./my-project --summary
  $ ai-license-risk-analyzer scan --path ./my-project --no-ai
  $ ai-license-risk-analyzer scan --path ./my-project --json
  $ ai-license-risk-analyzer configure --key YOUR_GEMINI_API_KEY

${chalk.bold("Flags:")}
  ${chalk.cyan("--security")}      Check known CVEs via npm audit
  ${chalk.cyan("--supply-chain")}  Check typosquatting, OSV advisories, and lockfile integrity
  ${chalk.cyan("--explain-all")}   AI-explain every license including SAFE ones
  ${chalk.cyan("--no-ai")}         Skip license explanations entirely (fastest mode)
  ${chalk.cyan("--summary")}       Show only the summary counts, no package list
  ${chalk.cyan("--json")}          Machine-readable JSON output
`,
);

program.parse(process.argv);

// ─── Banner ───────────────────────────────────────────────────────────────────

function printBanner(projectPath, withSecurity, withSupply) {
  const W = 54;
  const border = chalk.cyan("  ╔" + "═".repeat(W) + "╗");
  const bottom = chalk.cyan("  ╚" + "═".repeat(W) + "╝");
  const empty = chalk.cyan("  ║" + " ".repeat(W) + "║");
  const row = (text) => {
    const pad = W - stripAnsi(text).length;
    const left = Math.floor(pad / 2);
    const right = pad - left;
    return (
      chalk.cyan("  ║") +
      " ".repeat(Math.max(0, left)) +
      text +
      " ".repeat(Math.max(0, right)) +
      chalk.cyan("║")
    );
  };

  console.log();
  console.log(border);
  console.log(empty);
  console.log(row(chalk.bold.white(" ██████╗ ████████╗  █████╗ ")));
  console.log(row(chalk.bold.white(" ██╔══██╗╚══██╔══╝ ██╔══██╗")));
  console.log(row(chalk.bold.white(" ██║  ██║   ██║    ███████║")));
  console.log(row(chalk.bold.white(" ██║  ██║   ██║    ██╔══██║")));
  console.log(row(chalk.bold.white(" ██████╔╝   ██║    ██║  ██║")));
  console.log(row(chalk.bold.white(" ╚═════╝    ╚═╝    ╚═╝  ╚═╝")));
  console.log(empty);
  console.log(
    row(chalk.cyan.bold("AI License Risk Analyzer") + chalk.gray("  v1.0.0")),
  );
  console.log(row(chalk.gray("Licenses · CVEs · Supply Chain · Trust Score")));

  const aiStatus = hasApiKey()
    ? chalk.green("  ✦ Gemini AI: Live — plain-English explanations")
    : chalk.gray("  ◌ Gemini AI: Built-in knowledge base (offline)");
  console.log(row(aiStatus));

  const secStatus = withSecurity
    ? chalk.green("  🔒 Security: npm audit enabled               ")
    : chalk.gray("  🔓 Security: off  (add --security to enable)");
  console.log(row(secStatus));

  const supplyStatus = withSupply
    ? chalk.green("  🧬 Supply Chain: OSV + typo + integrity scan")
    : chalk.gray("  🧬 Supply Chain: off  (add --supply-chain)  ");
  console.log(row(supplyStatus));

  console.log(empty);
  console.log(bottom);
  console.log();
  console.log(chalk.gray(`  Project  `) + chalk.white(projectPath));
  console.log(
    chalk.gray(`  Time     `) + chalk.white(new Date().toLocaleString()),
  );
  console.log();
}

function formatProjectDisplayPath(projectRoot) {
  const rel = path.relative(process.cwd(), projectRoot);
  return rel || ".";
}

// ─── Package table ────────────────────────────────────────────────────────────

function printPackageTable(classified, transitiveRows = []) {
  // Sort: HIGH_RISK → WARNING → SAFE; within same risk, flagged packages first
  const order = { HIGH_RISK: 0, WARNING: 1, SAFE: 2 };
  const sorted = [...classified].sort((a, b) => {
    const riskDiff = order[a.risk] - order[b.risk];
    if (riskDiff !== 0) return riskDiff;

    const aSignals = (a.vulns?.length || 0) + (a.supplySignals?.length || 0);
    const bSignals = (b.vulns?.length || 0) + (b.supplySignals?.length || 0);
    if (aSignals !== bSignals) return bSignals - aSignals;

    return (a.trustScore || 100) - (b.trustScore || 100);
  });

  const allRows = [...sorted, ...transitiveRows];

  // Compute table widths from data to keep output aligned for mixed projects.
  const colName = Math.min(
    Math.max(...allRows.map((p) => p.name.length), 10),
    35,
  );
  const colVer = Math.min(
    Math.max(...allRows.map((p) => p.version.length), 7),
    15,
  );
  const colLic = Math.min(
    Math.max(...allRows.map((p) => p.license.length), 7),
    20,
  );

  const divider =
    "  " +
    chalk.gray(
      "─".repeat(4) +
        "─".repeat(colName + 2) +
        "─".repeat(colVer + 2) +
        "─".repeat(colLic + 2) +
        "─".repeat(12) +
        "─".repeat(8),
    );

  console.log(
    "  " +
      chalk.gray.bold(
        "    " +
          "Package".padEnd(colName + 2) +
          "Version".padEnd(colVer + 2) +
          "License".padEnd(colLic + 2) +
          "Risk".padEnd(12) +
          "Trust",
      ),
  );
  console.log(divider);

  // ── Direct dependency rows ───────────────────────────────────────────────────
  let lastRisk = null;
  for (const pkg of sorted) {
    if (lastRisk && lastRisk !== pkg.risk) console.log();
    lastRisk = pkg.risk;

    const hasVulns = pkg.vulns?.length > 0;
    const hasSupplySignals = pkg.supplySignals?.length > 0;
    const icon = hasVulns ? chalk.red("⚠") : ICON[pkg.risk];
    const label = LABEL[pkg.risk];
    const name = chalk.bold(pkg.name.slice(0, colName).padEnd(colName));
    const version = chalk.gray(pkg.version.slice(0, colVer).padEnd(colVer));
    const license = pkg.license.slice(0, colLic).padEnd(colLic);
    const licCol = RISK_COLOR[pkg.risk](license);
    const trust = formatTrustScore(pkg.trustScore ?? 100);
    const vulnBadge = hasVulns
      ? "  " +
        chalk.red.bold(
          `+ ${pkg.vulns.length} CVE${pkg.vulns.length > 1 ? "s" : ""}`,
        )
      : "";
    const supplyBadge = hasSupplySignals
      ? "  " + chalk.magenta.bold(`+ ${pkg.supplySignals.length} supply`)
      : "";

    console.log(
      `  ${icon}  ${name}  ${version}  ${licCol}  ${label} ${trust}${vulnBadge}${supplyBadge}`,
    );

    if (pkg.aiExplanation) printAIBlock(pkg.aiExplanation, pkg.risk);
    if (hasVulns) printSecurityBlock(pkg.vulns);
    if (hasSupplySignals) printSupplyChainBlock(pkg.supplySignals);
    if (pkg.remediation) printRemediationLine(pkg.remediation);
  }

  // ── Transitive-only vulnerable packages section ──────────────────────────────
  if (transitiveRows.length > 0) {
    console.log();
    console.log(
      chalk.gray("  ─── ") +
        chalk.red.bold("🔗 Vulnerable Transitive Dependencies") +
        chalk.gray(" (not in your package.json) ───"),
    );
    console.log(
      chalk.gray("      These were pulled in by your direct dependencies."),
    );
    console.log();

    for (const pkg of transitiveRows) {
      const worstSev = pkg.vulns[0]?.severity || "moderate";
      const sevColor = SEV_COLOR[worstSev] || chalk.yellow;
      const icon = chalk.red("⚠");
      const name = chalk.bold.red(pkg.name.slice(0, colName).padEnd(colName));
      const version = chalk.gray(pkg.version.slice(0, colVer).padEnd(colVer));
      const licStr = pkg.license.slice(0, colLic).padEnd(colLic);
      const trust = formatTrustScore(pkg.trustScore ?? 100);
      const vulnBadge = chalk.red.bold(
        `+ ${pkg.vulns.length} CVE${pkg.vulns.length > 1 ? "s" : ""}`,
      );

      console.log(
        `  ${icon}  ${name}  ${version}  ${chalk.gray(licStr)}  ${sevColor(worstSev.toUpperCase().padEnd(8))} ${trust}  ${vulnBadge}`,
      );
      printSecurityBlock(pkg.vulns);
      if (pkg.remediation) printRemediationLine(pkg.remediation);
    }
  }

  console.log(divider);
  console.log();
}

// ─── AI explanation block ─────────────────────────────────────────────────────

function printAIBlock(explanation, risk) {
  const indent = "       ";
  const color = RISK_COLOR[risk] || chalk.gray;
  const lines = explanation.split("\n").filter((l) => l.trim().length > 0);

  if (lines.length === 1) {
    console.log(chalk.italic.gray(`${indent}↳ ${lines[0]}`));
    return;
  }

  const aiLabel = hasApiKey()
    ? "🤖 Gemini AI — License Analysis"
    : "🗂  Built-in Knowledge Base";
  console.log(
    chalk.gray(
      `${indent}┌─ ${aiLabel} ${"─".repeat(Math.max(0, 42 - aiLabel.length))}`,
    ),
  );

  for (const line of lines) {
    const m = line.match(/^(📖|✅|📋|💡)\s+([^:]+:)\s*(.*)/u);
    if (m) {
      const [, emoji, labelPart, valuePart] = m;
      console.log(
        chalk.gray(`${indent}│ `) +
          chalk.bold.white(`${emoji} ${labelPart}`) +
          " " +
          color(valuePart),
      );
    } else {
      const formatted = line.replace(/^([^:]+:)/, (_, lbl) => chalk.bold(lbl));
      console.log(chalk.gray(`${indent}│ `) + color(formatted));
    }
  }
  console.log(chalk.gray(`${indent}└${"─".repeat(50)}`));
}

// ─── Security block ───────────────────────────────────────────────────────────

function printSecurityBlock(vulns) {
  const indent = "       ";

  console.log(
    chalk.red(`${indent}┌─ 🔒 Security Vulnerabilities ${"─".repeat(20)}`),
  );

  for (const v of vulns) {
    const sevColor = SEV_COLOR[v.severity] || chalk.white;
    const icon = SEV_ICON[v.severity] || "❓";
    const sevLabel = sevColor(`${icon} ${v.severity.toUpperCase().padEnd(8)}`);

    // Title
    console.log(
      chalk.red(`${indent}│ `) +
        sevLabel +
        "  " +
        chalk.white.bold(truncate(v.title, 40)),
    );

    // Affected version range
    if (v.affectedRange) {
      console.log(
        chalk.red(`${indent}│ `) +
          chalk.gray("            Affected: ") +
          chalk.yellow(v.affectedRange),
      );
    }

    // Fix info
    if (v.fixHint) {
      console.log(
        chalk.red(`${indent}│ `) +
          chalk.gray("            Fix:      ") +
          chalk.green(v.fixHint),
      );
    } else {
      console.log(
        chalk.red(`${indent}│ `) +
          chalk.gray("            Fix:      ") +
          chalk.red.dim("No fix available yet — consider an alternative"),
      );
    }

    // Advisory link
    if (v.url) {
      console.log(
        chalk.red(`${indent}│ `) +
          chalk.gray("            More:     ") +
          chalk.cyan.underline(v.url),
      );
    }

    // Dependency type badge
    const depType = v.isDirect
      ? chalk.yellow.bold("⚡ Direct dependency — you control this")
      : chalk.gray("🔗 Transitive — fix by updating parent package");
    console.log(
      chalk.red(`${indent}│ `) + chalk.gray("            ") + depType,
    );
  }

  console.log(chalk.red(`${indent}└${"─".repeat(50)}`));
}

// ─── Supply-chain block ──────────────────────────────────────────────────────

function printSupplyChainBlock(signals) {
  const indent = "       ";

  console.log(
    chalk.magenta(`${indent}┌─ 🧬 Supply-Chain Indicators ${"─".repeat(20)}`),
  );

  for (const signal of signals) {
    const sevColor = SUPPLY_SEV_COLOR[signal.severity] || chalk.gray;
    const sevIcon = SUPPLY_SEV_ICON[signal.severity] || "⚑";
    const sevLabel = sevColor(
      `${sevIcon} ${String(signal.severity || "low")
        .toUpperCase()
        .padEnd(8)}`,
    );

    console.log(
      chalk.magenta(`${indent}│ `) +
        sevLabel +
        "  " +
        chalk.white.bold(truncate(signal.title || "Supply-chain signal", 38)),
    );

    if (signal.detail) {
      console.log(
        chalk.magenta(`${indent}│ `) +
          chalk.gray("            Detail:   ") +
          chalk.white(truncate(signal.detail, 78)),
      );
    }

    if (signal.source) {
      console.log(
        chalk.magenta(`${indent}│ `) +
          chalk.gray("            Source:   ") +
          chalk.cyan(signal.source),
      );
    }
  }

  console.log(chalk.magenta(`${indent}└${"─".repeat(50)}`));
}

function printRemediationLine(remediation) {
  const indent = "       ";
  console.log(
    chalk.blue(`${indent}↳ 🛠  Remediation: `) + chalk.white(remediation),
  );
}

// ─── License summary box ──────────────────────────────────────────────────────

function printLicenseSummaryBox({ SAFE, WARNING, HIGH_RISK }) {
  const total = SAFE + WARNING + HIGH_RISK;
  const bar = (count, color) => {
    const filled = total > 0 ? Math.round((count / total) * 16) : 0;
    return color("█".repeat(filled)) + chalk.gray("░".repeat(16 - filled));
  };

  console.log(chalk.bold.white("  📋 License Summary"));
  console.log(chalk.gray("  " + "─".repeat(44)));
  console.log(
    `  ${ICON.SAFE}   ${chalk.green.bold("Safe      ")}  ${String(SAFE).padStart(3)}   ${bar(SAFE, chalk.green)}`,
  );
  console.log(
    `  ${ICON.WARNING}   ${chalk.yellow.bold("Warning   ")}  ${String(WARNING).padStart(3)}   ${bar(WARNING, chalk.yellow)}`,
  );
  console.log(
    `  ${ICON.HIGH_RISK}   ${chalk.red.bold("High Risk ")}  ${String(HIGH_RISK).padStart(3)}   ${bar(HIGH_RISK, chalk.red)}`,
  );
  console.log(chalk.gray("  " + "─".repeat(44)));
  console.log(chalk.gray("  Total") + `         ${total}`);
  console.log();

  if (HIGH_RISK > 0) {
    console.log(
      chalk.red.bold(
        `  ✖  ${HIGH_RISK} high-risk license(s) detected. Review before shipping.\n`,
      ),
    );
  } else if (WARNING > 0) {
    console.log(
      chalk.yellow.bold(
        `  ⚠  ${WARNING} license(s) need review. Check with your legal team.\n`,
      ),
    );
  } else {
    console.log(
      chalk.green.bold(
        `  ✔  All ${total} licenses look safe. You're good to go!\n`,
      ),
    );
  }
}

// ─── Security summary box ─────────────────────────────────────────────────────

function printSecuritySummaryBox(summary) {
  const { critical = 0, high = 0, moderate = 0, low = 0, info = 0 } = summary;
  const total = critical + high + moderate + low + info;
  const barTotal = total || 1;

  console.log(
    chalk.bold.white("  🔒 Security Summary  ") + chalk.gray("(npm audit)"),
  );
  console.log(chalk.gray("  " + "─".repeat(44)));

  const rows = [
    { label: "💀 Critical ", count: critical, color: chalk.red.bold },
    { label: "🔴 High     ", count: high, color: chalk.red },
    { label: "🟡 Moderate ", count: moderate, color: chalk.yellow },
    { label: "🟢 Low      ", count: low, color: chalk.green },
    { label: "🔵 Info     ", count: info, color: chalk.gray },
  ];

  for (const { label, count, color } of rows) {
    const filled = Math.round((count / barTotal) * 16);
    const bar = color("█".repeat(filled)) + chalk.gray("░".repeat(16 - filled));
    console.log(`  ${color(label)}  ${String(count).padStart(3)}   ${bar}`);
  }

  console.log(chalk.gray("  " + "─".repeat(44)));
  console.log(chalk.gray("  Total") + `         ${total}`);
  console.log();

  if (critical > 0) {
    console.log(
      chalk.red.bold(
        `  💀 ${critical} CRITICAL vulnerability(s)! Patch immediately before any deployment.\n`,
      ),
    );
  } else if (high > 0) {
    console.log(
      chalk.red.bold(
        `  🔴 ${high} high-severity CVE(s) — fix before your next release.\n`,
      ),
    );
  } else if (moderate > 0) {
    console.log(
      chalk.yellow.bold(
        `  🟡 ${moderate} moderate vulnerability(s) — plan to resolve soon.\n`,
      ),
    );
  } else if (low + info > 0) {
    console.log(
      chalk.green.bold(
        `  🟢 Only low/info issues found. Keep your dependencies updated.\n`,
      ),
    );
  } else {
    console.log(
      chalk.green.bold(
        `  ✔  No known vulnerabilities found. Great job keeping deps fresh! 🎉\n`,
      ),
    );
  }
}

// ─── Supply-chain summary box ────────────────────────────────────────────────

function printSupplyChainSummaryBox(summary) {
  const {
    totalSignals = 0,
    high = 0,
    moderate = 0,
    low = 0,
    typosquatSuspects = 0,
    osvAlerts = 0,
    maliciousAlerts = 0,
    integrityMismatchFlags = 0,
    missingIntegrityFlags = 0,
    weakIntegrityFlags = 0,
    incidentHistoryFlags = 0,
    recentPublishFlags = 0,
    singleMaintainerFlags = 0,
  } = summary || {};

  console.log(
    chalk.bold.white("  🧬 Supply-Chain Summary  ") +
      chalk.gray("(heuristics + OSV)"),
  );
  console.log(chalk.gray("  " + "─".repeat(52)));
  console.log(
    `  ${chalk.red.bold("High")}${" ".repeat(8)} ${String(high).padStart(3)}  ${chalk.red("Critical integrity / malicious / typo risks")}`,
  );
  console.log(
    `  ${chalk.yellow.bold("Moderate")}    ${String(moderate).padStart(3)}  ${chalk.yellow("OSV advisories, incident history, fresh release risk")}`,
  );
  console.log(
    `  ${chalk.cyan.bold("Low")}         ${String(low).padStart(3)}  ${chalk.cyan("Single maintainer / weak integrity heuristics")}`,
  );
  console.log(chalk.gray("  " + "─".repeat(52)));
  console.log(
    chalk.gray("  Signals") + `      ${String(totalSignals).padStart(3)}`,
  );
  console.log(
    chalk.gray("  Breakdown") +
      `    typo ${typosquatSuspects} · osv ${osvAlerts} · malicious ${maliciousAlerts}` +
      ` · mismatch ${integrityMismatchFlags} · missing ${missingIntegrityFlags}` +
      ` · weak ${weakIntegrityFlags} · incident ${incidentHistoryFlags}` +
      ` · recent ${recentPublishFlags} · single-maintainer ${singleMaintainerFlags}`,
  );
  console.log();

  if (high > 0 || typosquatSuspects > 0 || integrityMismatchFlags > 0) {
    console.log(
      chalk.red.bold(
        "  🚨 High-confidence supply-chain indicators found. Verify dependency provenance immediately.\n",
      ),
    );
  } else if (totalSignals > 0) {
    console.log(
      chalk.yellow.bold(
        "  ⚠ Supply-chain heuristics raised flags. Review before the next release.\n",
      ),
    );
  } else {
    console.log(
      chalk.green.bold("  ✔ No supply-chain indicators found in this scan.\n"),
    );
  }
}

// ─── Trust dashboard ─────────────────────────────────────────────────────────

function printTrustDashboard(trust) {
  const scoreColor =
    trust.overallScore >= 85
      ? chalk.green.bold
      : trust.overallScore >= 70
        ? chalk.yellow.bold
        : trust.overallScore >= 50
          ? ORANGE
          : chalk.red.bold;

  console.log(chalk.bold.white("  🛡️ Unified Trust Dashboard"));
  console.log(chalk.gray("  " + "─".repeat(52)));
  console.log(
    `  Overall Trust Score   ${scoreColor(String(trust.overallScore).padStart(3) + "/100")}  ${chalk.gray(`(${trust.band})`)}`,
  );
  console.log(
    `  Packages Assessed     ${String(trust.packageCount).padStart(3)}`,
  );
  console.log(
    `  Flagged Packages      ${String(trust.flaggedPackages).padStart(3)}`,
  );
  console.log(chalk.gray("  " + "─".repeat(52)));

  if (trust.topRisks.length === 0) {
    console.log(
      chalk.green("  ✔ No risky packages surfaced in trust ranking."),
    );
    console.log();
    return;
  }

  console.log(chalk.gray("  Lowest Trust Packages"));
  for (const item of trust.topRisks) {
    const trustText = formatTrustScore(item.score);
    const cveText =
      item.cveCount > 0
        ? chalk.red(`${item.cveCount} CVE`)
        : chalk.gray("0 CVE");
    const supplyText =
      item.supplyCount > 0
        ? chalk.magenta(`${item.supplyCount} supply`)
        : chalk.gray("0 supply");

    console.log(
      `  • ${chalk.bold(item.name)} ${chalk.gray(item.version)}  ${trustText}  ${RISK_COLOR[item.licenseRisk](item.licenseRisk)}  ${cveText}  ${supplyText}`,
    );

    if (item.remediation) {
      console.log(chalk.blue("      ↳ ") + chalk.white(item.remediation));
    }
  }
  console.log();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildLicenseSummary(packages) {
  return packages.reduce(
    (acc, pkg) => {
      acc[pkg.risk] += 1;
      return acc;
    },
    { SAFE: 0, WARNING: 0, HIGH_RISK: 0 },
  );
}

function buildTrustDashboard(
  classified,
  transitiveRows,
  secSummary,
  supplySummary,
) {
  const mergedRows = [...classified, ...transitiveRows];

  // Intentionally mutates each row so trustScore is available to downstream
  // ranking and remediation selection.
  for (const pkg of mergedRows) {
    pkg.trustScore = calculatePackageTrust(pkg);
  }

  const packageCount = mergedRows.length;
  const flaggedPackages = mergedRows.filter(
    (pkg) =>
      pkg.risk !== "SAFE" ||
      (pkg.vulns?.length || 0) > 0 ||
      (pkg.supplySignals?.length || 0) > 0,
  ).length;

  const averageScore =
    packageCount > 0
      ? Math.round(
          mergedRows.reduce((acc, pkg) => acc + (pkg.trustScore || 100), 0) /
            packageCount,
        )
      : 100;

  const criticalPenalty = (secSummary?.critical || 0) * 2;
  const supplyPenalty = Math.round((supplySummary?.ecosystemPenalty || 0) / 12);
  const overallScore = clamp(
    averageScore - criticalPenalty - supplyPenalty,
    0,
    100,
  );

  const topRisks = [...mergedRows]
    .sort((a, b) => (a.trustScore || 100) - (b.trustScore || 100))
    .slice(0, 5)
    .map((pkg) => ({
      name: pkg.name,
      version: pkg.version,
      score: pkg.trustScore || 100,
      licenseRisk: pkg.risk,
      cveCount: pkg.vulns?.length || 0,
      supplyCount: pkg.supplySignals?.length || 0,
      remediation: pkg.remediation || null,
    }));

  return {
    overallScore,
    band: trustBandFromScore(overallScore),
    packageCount,
    flaggedPackages,
    topRisks,
  };
}

function pickRemediationTargets(classified, transitiveRows, limit = 5) {
  const mergedRows = [...classified, ...transitiveRows];

  return mergedRows
    .filter(
      (pkg) =>
        pkg.risk !== "SAFE" ||
        (pkg.vulns?.length || 0) > 0 ||
        (pkg.supplySignals?.length || 0) > 0,
    )
    .sort((a, b) => (a.trustScore || 100) - (b.trustScore || 100))
    .slice(0, limit);
}

function calculatePackageTrust(pkg) {
  // Deterministic additive penalty model with caps to prevent one category
  // from dominating the package trust score completely.
  const licensePenalty =
    pkg.risk === "HIGH_RISK" ? 45 : pkg.risk === "WARNING" ? 18 : 0;

  const vulnPenalty = (pkg.vulns || []).reduce((acc, vuln) => {
    const sev = vuln.severity || "moderate";
    const weight =
      sev === "critical"
        ? 30
        : sev === "high"
          ? 20
          : sev === "moderate"
            ? 10
            : sev === "low"
              ? 4
              : 2;
    return acc + weight;
  }, 0);

  const supplyPenalty = (pkg.supplySignals || []).reduce((acc, signal) => {
    const sev = signal.severity || "low";
    const weight = sev === "high" ? 15 : sev === "moderate" ? 8 : 4;
    return acc + weight;
  }, 0);

  return clamp(
    100 -
      licensePenalty -
      Math.min(vulnPenalty, 70) -
      Math.min(supplyPenalty, 40),
    0,
    100,
  );
}

function trustBandFromScore(score) {
  if (score >= 85) return "Strong";
  if (score >= 70) return "Watch";
  if (score >= 50) return "High Caution";
  return "Critical";
}

function formatTrustScore(score) {
  const n = clamp(Math.round(score), 0, 100);
  if (n >= 85) return chalk.green.bold(`${String(n).padStart(3)}/100`);
  if (n >= 70) return chalk.yellow.bold(`${String(n).padStart(3)}/100`);
  if (n >= 50) return ORANGE(`${String(n).padStart(3)}/100`);
  return chalk.red.bold(`${String(n).padStart(3)}/100`);
}

function buildPkgKey(pkg) {
  return `${pkg.name}@${pkg.version}`;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function truncate(str, maxLen) {
  if (!str) return "";
  return str.length > maxLen ? str.slice(0, maxLen - 3) + "..." : str;
}

function stripAnsi(str) {
  return str.replace(/\x1B\[[0-9;]*m/g, "");
}
