// ─── Risk level constants ─────────────────────────────────────────────────────

/** @typedef {'SAFE' | 'WARNING' | 'HIGH_RISK'} RiskLevel */

/**
 * @typedef {Object} ClassificationResult
 * @property {RiskLevel} risk    - Risk tier for the license.
 * @property {string}    message - Short, human-readable explanation.
 */

// ─── License rule tables ──────────────────────────────────────────────────────
// Each entry is a substring/keyword matched case-insensitively against the
// license string. Add new entries here to extend coverage — no other code
// needs to change.

const RULES = [
  // ── WARNING (LGPL) — must come BEFORE HIGH_RISK ───────────────────────────
  // Checked first so 'LGPL-3.0' is not substring-matched by 'GPL-3.0' below.
  {
    risk: 'WARNING',
    keywords: ['LGPL-3.0', 'LGPL-2.1', 'LGPL-2.0'],
    message:
      'Weak copyleft (LGPL). Linking in proprietary apps is allowed, but ' +
      'modifications to the library itself must remain open-source.',
  },

  // ── HIGH_RISK ──────────────────────────────────────────────────────────────
  // Strong copyleft: requires derivative works to be released under the same
  // license, which is incompatible with most commercial / proprietary software.
  {
    risk: 'HIGH_RISK',
    keywords: ['GPL-3.0', 'GPL-2.0', 'GPL-1.0', 'AGPL-3.0', 'AGPL-1.0'],
    message:
      'Strong copyleft (GPL/AGPL). Derivative works must be released under ' +
      'the same license. Incompatible with proprietary software.',
  },

  // ── WARNING (other weak copyleft / unknown) ────────────────────────────────
  {
    risk: 'WARNING',
    keywords: [
      'MPL-2.0',                               // file-level copyleft
      'CDDL-1.0',                              // incompatible with GPL
      'EPL-2.0', 'EPL-1.0',                   // weak copyleft (Eclipse)
      'EUPL-1.1', 'EUPL-1.2',                 // EU public license
      'CC-BY-SA',                              // share-alike (not for software)
      'Unknown', 'UNKNOWN',                    // no license info — treat with caution
    ],
    message:
      'Weak copyleft or unknown. Some restrictions apply — review before ' +
      'using in proprietary or commercial software.',
  },

  // ── SAFE ──────────────────────────────────────────────────────────────────
  // Permissive: minimal conditions (attribution), compatible with commercial use.
  {
    risk: 'SAFE',
    keywords: [
      'MIT',
      'ISC',
      'Apache-2.0', 'Apache 2.0',
      'BSD-2-Clause', 'BSD-3-Clause', 'BSD-4-Clause',
      'CC0-1.0',          // public domain dedication
      'Unlicense',        // public domain
      'WTFPL',            // anything-goes license
      '0BSD',             // zero-clause BSD
    ],
    message:
      'Permissive license. Free to use, modify, and distribute with ' +
      'attribution. Compatible with commercial and proprietary software.',
  },
];

// ─── classifyLicense ─────────────────────────────────────────────────────────

/**
 * Classifies a license string into a risk tier.
 *
 * Matching is keyword-based and case-insensitive, so partial strings like
 * "MIT AND Apache-2.0" or "GPL-3.0-only" are handled correctly.
 *
 * Precedence: HIGH_RISK > WARNING > SAFE
 * (rules are evaluated in RULES array order — most severe first)
 *
 * @param {string} license - License identifier string (SPDX or free-form).
 * @returns {ClassificationResult}
 *
 * @example
 * classifyLicense('MIT')
 * // { risk: 'SAFE', message: 'Permissive license...' }
 *
 * classifyLicense('GPL-3.0-or-later')
 * // { risk: 'HIGH_RISK', message: 'Strong copyleft...' }
 *
 * classifyLicense('Unknown')
 * // { risk: 'WARNING', message: 'Weak copyleft or unknown...' }
 */
export function classifyLicense(license) {
  if (!license || license.trim() === '') {
    return {
      risk: 'WARNING',
      message:
        'No license information found. Treat as unknown — review the ' +
        'package source before use.',
    };
  }

  const normalized = license.trim();

  for (const rule of RULES) {
    const matched = rule.keywords.some((kw) =>
      normalized.toLowerCase().includes(kw.toLowerCase())
    );

    if (matched) {
      return { risk: rule.risk, message: rule.message };
    }
  }

  // Fallback — license string exists but didn't match any known pattern
  return {
    risk: 'WARNING',
    message: `Unrecognized license "${normalized}". Review manually before use.`,
  };
}

// ─── analyzeRisks ─────────────────────────────────────────────────────────────

/**
 * @typedef {Object} AnalyzedPackage
 * @property {string}    name       - Package name.
 * @property {string}    version    - Package version.
 * @property {string}    license    - License identifier.
 * @property {RiskLevel} risk       - Classified risk tier.
 * @property {string}    message    - Explanation for the risk tier.
 * @property {string|null} repository - Repository URL if available.
 */

/**
 * Runs classifyLicense on every scanned package and returns a full risk report.
 *
 * @param {import('./scanner.js').ScannedPackage[]} packages - Output of scanLicenses().
 * @returns {{
 *   summary: { SAFE: number, WARNING: number, HIGH_RISK: number },
 *   packages: AnalyzedPackage[]
 * }}
 */
export function analyzeRisks(packages) {
  const summary = { SAFE: 0, WARNING: 0, HIGH_RISK: 0 };
  const results = [];

  for (const pkg of packages) {
    const { risk, message } = classifyLicense(pkg.license);
    summary[risk] += 1;

    results.push({
      name: pkg.name,
      version: pkg.version,
      license: pkg.license,
      risk,
      message,
      repository: pkg.repository ?? null,
    });
  }

  // Sort by severity: HIGH_RISK → WARNING → SAFE
  const order = { HIGH_RISK: 0, WARNING: 1, SAFE: 2 };
  results.sort((a, b) => order[a.risk] - order[b.risk]);

  return { summary, packages: results };
}
