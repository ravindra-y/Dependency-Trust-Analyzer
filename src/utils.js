import chalk from 'chalk';

// ─── Risk display maps ─────────────────────────────────────────────────────────
// Keyed by the RiskLevel values from riskAnalyzer.js: SAFE | WARNING | HIGH_RISK

const RISK_COLOR = {
  SAFE:      chalk.green,
  WARNING:   chalk.yellow,
  HIGH_RISK: chalk.red,
};

const RISK_EMOJI = {
  SAFE:      '🟢',
  WARNING:   '🟡',
  HIGH_RISK: '🔴',
};

// Display order in tables — most severe first
const RISK_ORDER = ['HIGH_RISK', 'WARNING', 'SAFE'];

// ─── Full detailed report ─────────────────────────────────────────────────────

/**
 * Prints the full risk report:
 *   1. Summary count table (always)
 *   2. Per-package detail block for HIGH_RISK and WARNING packages
 *
 * @param {{ summary: Object, packages: import('./riskAnalyzer.js').AnalyzedPackage[] }} report
 */
export function printSummary({ summary, packages }) {
  printTableSummary(summary);

  const flagged = packages.filter((p) => p.risk === 'HIGH_RISK' || p.risk === 'WARNING');

  if (flagged.length === 0) {
    console.log(chalk.green('  ✅  All licenses are safe. No issues detected.\n'));
    return;
  }

  console.log(chalk.bold('  ⚠️   Packages Requiring Attention\n'));

  for (const pkg of flagged) {
    const color = RISK_COLOR[pkg.risk];
    const emoji = RISK_EMOJI[pkg.risk];

    console.log(`  ${emoji}  ${chalk.bold(pkg.name)}  ${chalk.gray(`v${pkg.version}`)}`);
    console.log(`       License : ${color(pkg.license)}`);
    console.log(`       Risk    : ${color(pkg.risk)}`);
    console.log(`       Note    : ${chalk.italic(pkg.message)}`);

    if (pkg.repository) {
      console.log(`       Repo    : ${chalk.gray(pkg.repository)}`);
    }

    console.log();
  }
}

// ─── Summary-only table ───────────────────────────────────────────────────────

/**
 * Prints a compact summary table with counts, ASCII bars, and percentages.
 * Used directly when --summary flag is passed.
 *
 * @param {{ SAFE: number, WARNING: number, HIGH_RISK: number }} summary
 */
export function printTableSummary(summary) {
  const total = Object.values(summary).reduce((acc, n) => acc + n, 0);

  console.log(chalk.bold('  📊  License Risk Summary\n'));
  console.log(`  ${'Risk Level'.padEnd(12)}  ${'Packages'.padEnd(10)}  Share`);
  console.log(`  ${'─'.repeat(38)}`);

  for (const level of RISK_ORDER) {
    const count = summary[level] ?? 0;
    const color = RISK_COLOR[level];
    const emoji = RISK_EMOJI[level];
    const pct   = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';
    const bar   = buildBar(count, total, 12);

    console.log(
      `  ${emoji}  ${color(level.padEnd(10))}  ${String(count).padEnd(10)}  ${chalk.gray(bar)}  ${pct}%`
    );
  }

  console.log(`  ${'─'.repeat(38)}`);
  console.log(`  ${'TOTAL'.padEnd(14)}  ${total}\n`);
}

// ─── Helper ───────────────────────────────────────────────────────────────────

/**
 * Builds a fixed-width ASCII progress bar.
 * @param {number} count
 * @param {number} total
 * @param {number} width
 * @returns {string}
 */
function buildBar(count, total, width) {
  if (total === 0) return '░'.repeat(width);
  const filled = Math.round((count / total) * width);
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}
