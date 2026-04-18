import { execSync } from 'child_process';
import path         from 'path';

// ─── Types (JSDoc) ────────────────────────────────────────────────────────────

/**
 * @typedef {Object} Vulnerability
 * @property {string}      package       - Package name.
 * @property {string}      severity      - 'critical' | 'high' | 'moderate' | 'low' | 'info'
 * @property {string}      title         - Short description of the vulnerability.
 * @property {string|null} url           - Advisory URL (GitHub/npm advisory).
 * @property {string|null} fixVersion    - Specific version that fixes this (if known).
 * @property {string|null} fixAvailable  - Human-readable fix hint.
 * @property {string|null} affectedRange - Version range affected.
 * @property {boolean}     isDirect      - true if it is a direct dependency.
 * @property {boolean}     isTransitive  - true if it is only a transitive dependency.
 */

/**
 * @typedef {Object} SecurityScanResult
 * @property {Map<string, Vulnerability[]>} vulnsByPackage - Map of packageName → vulnerabilities.
 * @property {{ critical:number, high:number, moderate:number, low:number, info:number, total:number }} summary
 * @property {string[]} transitiveOnly - Names of packages only found as transitive deps.
 */

// ─── Severity metadata ────────────────────────────────────────────────────────

export const SEV_ORDER = ['critical', 'high', 'moderate', 'low', 'info'];

export const SEV_ICON = {
  critical: '💀',
  high:     '🔴',
  moderate: '🟡',
  low:      '🟢',
  info:     '🔵',
};

// ─── Main scanner ─────────────────────────────────────────────────────────────

/**
 * Runs `npm audit --json` in the given project directory and returns
 * structured vulnerability data. Handles both npm 6 and npm 7+ output formats.
 *
 * npm audit exits with a non-zero code when vulnerabilities are found —
 * this is normal. We always capture stdout and continue.
 *
 * @param {string} projectPath - Relative or absolute path to the project root.
 * @returns {Promise<SecurityScanResult>}
 */
export async function runSecurityScan(projectPath) {
  const resolvedPath = path.resolve(projectPath);

  // ── Run npm audit ────────────────────────────────────────────────────────────
  let raw = '';
  try {
    raw = execSync('npm audit --json', {
      cwd:     resolvedPath,
      stdio:   ['pipe', 'pipe', 'pipe'],
      timeout: 30_000,
    }).toString();
  } catch (err) {
    // npm audit exits 1 when vulnerabilities exist — stdout is still valid JSON.
    raw = err.stdout?.toString() || '';
    if (!raw) {
      const stderr = err.stderr?.toString() || '';
      // Check for common non-vuln errors
      if (stderr.includes('ENOLOCK') || stderr.includes('package-lock')) {
        throw new Error('No package-lock.json found. Run "npm install" first.');
      }
      throw new Error(`npm audit failed: ${stderr || err.message}`);
    }
  }

  // ── Parse JSON ───────────────────────────────────────────────────────────────
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      'Could not parse npm audit output. ' +
      'Ensure npm is installed and the project has been npm-installed.'
    );
  }

  // ── Build vulnerability map ──────────────────────────────────────────────────
  const vulnsByPackage = new Map();
  const seenAdvisories = new Set(); // deduplicate by advisory URL

  if (parsed.auditReportVersion === 2 && parsed.vulnerabilities) {
    // ── npm 7+ format ─────────────────────────────────────────────────────────
    for (const [pkgName, vuln] of Object.entries(parsed.vulnerabilities)) {
      const vias       = Array.isArray(vuln.via) ? vuln.via : [];
      const advisories = vias.filter((v) => typeof v === 'object' && v !== null);

      // Determine fix information
      let fixVersion  = null;
      let fixHint     = null;
      if (typeof vuln.fixAvailable === 'object' && vuln.fixAvailable !== null) {
        fixVersion = vuln.fixAvailable.version;
        fixHint    = `npm install ${vuln.fixAvailable.name}@${vuln.fixAvailable.version}`;
      } else if (vuln.fixAvailable === true) {
        fixHint = 'npm audit fix';
      } else {
        fixHint = null; // no fix available
      }

      if (advisories.length === 0) {
        // Transitive with no advisory details — create one summary entry
        _addVuln(vulnsByPackage, pkgName, {
          package:       pkgName,
          severity:      vuln.severity,
          title:         'Vulnerable via transitive dependency chain',
          url:           null,
          fixVersion,
          fixHint,
          affectedRange: vuln.range || null,
          isDirect:      vuln.isDirect  ?? false,
          isTransitive:  !(vuln.isDirect ?? false),
        });
      } else {
        for (const adv of advisories) {
          // Deduplicate same advisory appearing on multiple packages
          const dedupKey = `${pkgName}::${adv.url || adv.title}`;
          if (seenAdvisories.has(dedupKey)) continue;
          seenAdvisories.add(dedupKey);

          _addVuln(vulnsByPackage, pkgName, {
            package:       pkgName,
            severity:      adv.severity   || vuln.severity,
            title:         adv.title      || 'Unknown vulnerability',
            url:           adv.url        || null,
            fixVersion,
            fixHint,
            affectedRange: adv.range      || vuln.range || null,
            isDirect:      vuln.isDirect  ?? false,
            isTransitive:  !(vuln.isDirect ?? false),
          });
        }
      }
    }
  } else if (parsed.advisories) {
    // ── npm 6 format ──────────────────────────────────────────────────────────
    for (const adv of Object.values(parsed.advisories)) {
      const pkgName  = adv.module_name;
      const hasfix   = adv.patched_versions && adv.patched_versions !== '<0.0.0';
      const fixVersion = hasfix ? null : null; // npm 6 gives ranges, not exact versions
      const fixHint    = hasfix
        ? `Update to ${adv.patched_versions}`
        : null;

      _addVuln(vulnsByPackage, pkgName, {
        package:       pkgName,
        severity:      adv.severity,
        title:         adv.title || 'Unknown vulnerability',
        url:           adv.url   || null,
        fixVersion,
        fixHint,
        affectedRange: adv.vulnerable_versions || null,
        isDirect:      false, // npm 6 doesn't expose this reliably
        isTransitive:  false,
      });
    }
  }

  // ── Sort each package's vulns by severity (most severe first) ───────────────
  for (const [pkgName, vulns] of vulnsByPackage) {
    vulnsByPackage.set(
      pkgName,
      vulns.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    );
  }

  // ── Identify transitive-only packages (not in package.json directly) ─────────
  const transitiveOnly = [...vulnsByPackage.keys()].filter((name) => {
    const vulns = vulnsByPackage.get(name);
    return vulns.every((v) => v.isTransitive);
  });

  // ── Summary ──────────────────────────────────────────────────────────────────
  const summary = parsed.metadata?.vulnerabilities ?? _countSeverities(vulnsByPackage);

  return { vulnsByPackage, summary, transitiveOnly };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _addVuln(map, pkgName, vuln) {
  if (!map.has(pkgName)) map.set(pkgName, []);
  map.get(pkgName).push(vuln);
}

function _countSeverities(vulnsByPackage) {
  const counts = { critical: 0, high: 0, moderate: 0, low: 0, info: 0, total: 0 };
  for (const vulns of vulnsByPackage.values()) {
    for (const v of vulns) {
      counts[v.severity] = (counts[v.severity] || 0) + 1;
      counts.total += 1;
    }
  }
  return counts;
}
