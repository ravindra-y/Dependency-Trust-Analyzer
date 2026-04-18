import fs from "fs";
import path from "path";
import axios from "axios";

// ─── Constants ────────────────────────────────────────────────────────────────

const OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const REGISTRY_BASE_URL = "https://registry.npmjs.org";

const POPULAR_PACKAGE_TARGETS = [
  "react",
  "vue",
  "angular",
  "lodash",
  "axios",
  "express",
  "typescript",
  "webpack",
  "jest",
  "eslint",
  "chalk",
  "commander",
  "dotenv",
  "uuid",
  "rxjs",
  "next",
  "prettier",
  "mocha",
  "babel",
  "tailwindcss",
];

const INCIDENT_WATCHLIST = {
  "event-stream": "Historical compromise in dependency chain (2018).",
  "ua-parser-js":
    "Maintainer account compromise led to malware release (2021).",
  coa: "Maintainer account compromise led to malicious versions (2021).",
  rc: "Maintainer account compromise led to malicious versions (2021).",
  colors:
    "Protestware incident affected package behavior and reliability (2022).",
  faker: "Protestware incident affected package reliability and trust (2022).",
  "node-ipc": "Controversial behavior change incident impacted trust (2022).",
};

const MALICIOUS_KEYWORDS = [
  "malicious",
  "backdoor",
  "typosquat",
  "compromise",
  "compromised",
  "dependency confusion",
  "protestware",
];

const SEVERITY_WEIGHT = {
  high: 15,
  moderate: 8,
  low: 4,
};

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * @typedef {Object} SupplySignal
 * @property {'high' | 'moderate' | 'low'} severity
 * @property {'TYPOSQUAT' | 'OSV_ALERT' | 'INCIDENT_HISTORY' | 'RECENT_PUBLISH' | 'SINGLE_MAINTAINER' | 'INTEGRITY_MISMATCH' | 'MISSING_INTEGRITY' | 'WEAK_INTEGRITY'} type
 * @property {string} title
 * @property {string} detail
 * @property {string=} source
 */

/**
 * @typedef {Object} SupplyChainResult
 * @property {Record<string, SupplySignal[]>} signalsByPackage
 * @property {{
 *   totalSignals: number,
 *   high: number,
 *   moderate: number,
 *   low: number,
 *   typosquatSuspects: number,
 *   osvAlerts: number,
 *   maliciousAlerts: number,
 *   incidentHistoryFlags: number,
 *   recentPublishFlags: number,
 *   singleMaintainerFlags: number,
 *   integrityMismatchFlags: number,
 *   missingIntegrityFlags: number,
 *   weakIntegrityFlags: number,
 *   ecosystemPenalty: number,
 *   warnings: string[]
 * }} summary
 */

/**
 * Runs supply-chain heuristics over resolved packages.
 *
 * Heuristics included:
 * - Typosquatting against common package names
 * - OSV.dev cross-reference for known vulnerabilities/malicious advisories
 * - Historical incident watchlist ("Axios-style risk" style indicator)
 * - Lockfile integrity checks (missing/weak/mismatch)
 * - NPM metadata checks (recent publish + single maintainer)
 *
 * @param {string} projectPath
 * @param {{ name: string, version: string }[]} packages
 * @returns {Promise<SupplyChainResult>}
 */
export async function runSupplyChainScan(projectPath, packages) {
  const resolvedPath = path.resolve(projectPath);
  const signalsByPackage = {};
  const warnings = [];

  const lockfileIndex = loadLockfileIndex(resolvedPath);
  const directDeps = loadDirectDependencyNames(resolvedPath);

  // Local/static checks first (fast + offline friendly).
  for (const pkg of packages) {
    const key = packageKey(pkg.name, pkg.version);

    const typo = detectTyposquat(pkg.name);
    if (typo) {
      addSignal(signalsByPackage, key, {
        severity: "high",
        type: "TYPOSQUAT",
        title: `Name resembles "${typo}"`,
        detail: `Potential typosquat pattern detected: "${pkg.name}" looks similar to "${typo}".`,
        source: "heuristic",
      });
    }

    const incidentReason = INCIDENT_WATCHLIST[pkg.name];
    if (incidentReason) {
      addSignal(signalsByPackage, key, {
        severity: "moderate",
        type: "INCIDENT_HISTORY",
        title: "Historical supply-chain incident indicator",
        detail: incidentReason,
        source: "watchlist",
      });
    }

    const integrity = lockfileIndex.byKey.get(key);
    if (integrity !== undefined) {
      if (!integrity) {
        addSignal(signalsByPackage, key, {
          severity: "moderate",
          type: "MISSING_INTEGRITY",
          title: "Missing lockfile integrity hash",
          detail:
            "package-lock.json entry has no integrity field for this package version.",
          source: "package-lock.json",
        });
      } else if (!integrity.startsWith("sha512-")) {
        addSignal(signalsByPackage, key, {
          severity: "low",
          type: "WEAK_INTEGRITY",
          title: "Weak integrity algorithm in lockfile",
          detail: `Integrity uses ${integrity.split("-")[0]} instead of sha512.`,
          source: "package-lock.json",
        });
      }
    }
  }

  // OSV cross-reference for known vulnerabilities / malicious advisories.
  try {
    await attachOsvSignals(packages, signalsByPackage);
  } catch (err) {
    warnings.push(`OSV scan skipped: ${err.message}`);
  }

  // NPM registry metadata checks (direct deps only to keep scan quick).
  try {
    await attachRegistrySignals(
      packages,
      directDeps,
      lockfileIndex,
      signalsByPackage,
    );
  } catch (err) {
    warnings.push(`Registry metadata checks partially skipped: ${err.message}`);
  }

  const summary = buildSummary(signalsByPackage, warnings);
  return { signalsByPackage, summary };
}

// ─── OSV ──────────────────────────────────────────────────────────────────────

async function attachOsvSignals(packages, signalsByPackage) {
  if (!packages.length) return;

  const chunkSize = 80;
  for (let i = 0; i < packages.length; i += chunkSize) {
    const chunk = packages.slice(i, i + chunkSize);
    const queries = chunk.map((pkg) => ({
      package: { name: pkg.name, ecosystem: "npm" },
      version: pkg.version,
    }));

    const response = await axios.post(
      OSV_QUERY_BATCH_URL,
      { queries },
      {
        timeout: 12_000,
        validateStatus: (status) => status >= 200 && status < 300,
      },
    );

    const results = response.data?.results || [];

    for (let index = 0; index < results.length; index += 1) {
      const pkg = chunk[index];
      const key = packageKey(pkg.name, pkg.version);
      const vulns = results[index]?.vulns || [];

      for (const vuln of vulns) {
        const summaryText =
          `${vuln.summary || ""} ${vuln.details || ""}`.toLowerCase();
        const isMalicious = MALICIOUS_KEYWORDS.some((kw) =>
          summaryText.includes(kw),
        );

        addSignal(signalsByPackage, key, {
          severity: isMalicious ? "high" : "moderate",
          type: "OSV_ALERT",
          title: isMalicious
            ? "OSV malicious/compromise indicator"
            : "OSV vulnerability advisory",
          detail: `${vuln.id || "OSV"}: ${truncate(vuln.summary || "Security advisory found", 120)}`,
          source:
            vuln.references?.[0]?.url ||
            `https://osv.dev/vulnerability/${vuln.id}`,
        });
      }
    }
  }
}

// ─── NPM Registry Metadata ────────────────────────────────────────────────────

async function attachRegistrySignals(
  packages,
  directDeps,
  lockfileIndex,
  signalsByPackage,
) {
  const directTargets = packages.filter((pkg) => directDeps.has(pkg.name));
  if (!directTargets.length) return;

  await runWithConcurrency(directTargets, 5, async (pkg) => {
    const key = packageKey(pkg.name, pkg.version);
    const metadata = await fetchNpmPackageMetadata(pkg.name);
    if (!metadata) return;

    const versionMeta = metadata.versions?.[pkg.version];
    const publishedAt = metadata.time?.[pkg.version]
      ? new Date(metadata.time[pkg.version])
      : null;
    const maintainersCount = Array.isArray(metadata.maintainers)
      ? metadata.maintainers.length
      : 0;

    if (publishedAt && isRecentDate(publishedAt, 7)) {
      addSignal(signalsByPackage, key, {
        severity: "moderate",
        type: "RECENT_PUBLISH",
        title: "Recently published dependency version",
        detail: `Version ${pkg.version} was published ${daysAgo(publishedAt)} day(s) ago.`,
        source: "registry.npmjs.org",
      });
    }

    if (maintainersCount > 0 && maintainersCount <= 1) {
      addSignal(signalsByPackage, key, {
        severity: "low",
        type: "SINGLE_MAINTAINER",
        title: "Single maintainer package risk",
        detail:
          "Package appears to have one maintainer; account compromise has higher impact.",
        source: "registry.npmjs.org",
      });
    }

    const lockIntegrity = lockfileIndex.byKey.get(key);
    const registryIntegrity = versionMeta?.dist?.integrity;
    if (
      lockIntegrity &&
      registryIntegrity &&
      lockIntegrity !== registryIntegrity
    ) {
      addSignal(signalsByPackage, key, {
        severity: "high",
        type: "INTEGRITY_MISMATCH",
        title: "Lockfile integrity mismatch",
        detail:
          "package-lock integrity does not match npm registry dist.integrity for this version.",
        source: "registry.npmjs.org vs package-lock.json",
      });
    }
  });
}

async function fetchNpmPackageMetadata(packageName) {
  const encoded = encodePackageName(packageName);
  const url = `${REGISTRY_BASE_URL}/${encoded}`;

  const response = await axios.get(url, {
    timeout: 10_000,
    validateStatus: (status) => status >= 200 && status < 500,
  });

  if (response.status >= 400) return null;
  return response.data;
}

// ─── Lockfile / package.json helpers ──────────────────────────────────────────

function loadDirectDependencyNames(projectPath) {
  const packageJsonPath = path.join(projectPath, "package.json");
  if (!fs.existsSync(packageJsonPath)) return new Set();

  const parsed = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
  return new Set([
    ...Object.keys(parsed.dependencies || {}),
    ...Object.keys(parsed.optionalDependencies || {}),
  ]);
}

function loadLockfileIndex(projectPath) {
  const lockPath = path.join(projectPath, "package-lock.json");
  const byKey = new Map();

  if (!fs.existsSync(lockPath)) return { byKey };

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  } catch {
    return { byKey };
  }

  // npm v7+ lockfile format
  if (parsed.packages && typeof parsed.packages === "object") {
    for (const [pkgPath, meta] of Object.entries(parsed.packages)) {
      if (!pkgPath.startsWith("node_modules/")) continue;
      const pkgName = pkgPath.slice("node_modules/".length);
      const version = meta?.version;
      if (!version) continue;
      byKey.set(packageKey(pkgName, version), meta?.integrity || null);
    }
    return { byKey };
  }

  // npm v6 lockfile format
  walkDependenciesV1(parsed.dependencies || {}, (name, meta) => {
    const version = meta?.version;
    if (!version) return;
    byKey.set(packageKey(name, version), meta?.integrity || null);
  });

  return { byKey };
}

function walkDependenciesV1(dependencies, onNode) {
  for (const [name, meta] of Object.entries(dependencies || {})) {
    onNode(name, meta || {});
    if (meta?.dependencies) {
      walkDependenciesV1(meta.dependencies, onNode);
    }
  }
}

// ─── Typosquat helpers ────────────────────────────────────────────────────────

function detectTyposquat(packageName) {
  const normalized = stripScope(packageName).toLowerCase();

  // Reduce false positives for naturally segmented names.
  if (
    normalized.includes("-") ||
    normalized.includes(".") ||
    normalized.includes("_")
  ) {
    return null;
  }

  if (normalized.length < 4) return null;

  for (const target of POPULAR_PACKAGE_TARGETS) {
    if (normalized === target) continue;

    // Avoid false positives for legitimate prefixed/suffixed packages
    // such as "gaxios" vs "axios".
    if (normalized.includes(target) || target.includes(normalized)) continue;

    const distance = levenshtein(normalized, target);
    const swap = isSingleAdjacentSwap(normalized, target);

    if ((distance === 1 || swap) && likelyHumanTypo(normalized, target)) {
      return target;
    }
  }

  return null;
}

function likelyHumanTypo(name, target) {
  const samePrefix = name[0] === target[0];
  const sameSuffix = name[name.length - 1] === target[target.length - 1];
  const lenDelta = Math.abs(name.length - target.length);
  return samePrefix && sameSuffix && lenDelta <= 1;
}

function stripScope(name) {
  if (!name.startsWith("@")) return name;
  const parts = name.split("/");
  return parts[1] || name;
}

function isSingleAdjacentSwap(a, b) {
  if (a.length !== b.length) return false;

  let firstMismatch = -1;
  let mismatchCount = 0;

  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      mismatchCount += 1;
      if (firstMismatch === -1) firstMismatch = i;
      if (mismatchCount > 2) return false;
    }
  }

  if (
    mismatchCount !== 2 ||
    firstMismatch < 0 ||
    firstMismatch >= a.length - 1
  ) {
    return false;
  }

  return (
    a[firstMismatch] === b[firstMismatch + 1] &&
    a[firstMismatch + 1] === b[firstMismatch]
  );
}

function levenshtein(a, b) {
  const rows = a.length + 1;
  const cols = b.length + 1;

  const matrix = Array.from({ length: rows }, () => new Array(cols).fill(0));

  for (let i = 0; i < rows; i += 1) matrix[i][0] = i;
  for (let j = 0; j < cols; j += 1) matrix[0][j] = j;

  for (let i = 1; i < rows; i += 1) {
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost,
      );
    }
  }

  return matrix[a.length][b.length];
}

// ─── Summary / scoring ────────────────────────────────────────────────────────

function buildSummary(signalsByPackage, warnings) {
  const summary = {
    totalSignals: 0,
    high: 0,
    moderate: 0,
    low: 0,
    typosquatSuspects: 0,
    osvAlerts: 0,
    maliciousAlerts: 0,
    incidentHistoryFlags: 0,
    recentPublishFlags: 0,
    singleMaintainerFlags: 0,
    integrityMismatchFlags: 0,
    missingIntegrityFlags: 0,
    weakIntegrityFlags: 0,
    ecosystemPenalty: 0,
    warnings,
  };

  for (const signals of Object.values(signalsByPackage)) {
    for (const signal of signals) {
      summary.totalSignals += 1;
      summary[signal.severity] += 1;
      summary.ecosystemPenalty += SEVERITY_WEIGHT[signal.severity] || 0;

      if (signal.type === "TYPOSQUAT") summary.typosquatSuspects += 1;
      if (signal.type === "OSV_ALERT") {
        summary.osvAlerts += 1;
        if (signal.title.toLowerCase().includes("malicious")) {
          summary.maliciousAlerts += 1;
        }
      }
      if (signal.type === "INCIDENT_HISTORY") summary.incidentHistoryFlags += 1;
      if (signal.type === "RECENT_PUBLISH") summary.recentPublishFlags += 1;
      if (signal.type === "SINGLE_MAINTAINER")
        summary.singleMaintainerFlags += 1;
      if (signal.type === "INTEGRITY_MISMATCH")
        summary.integrityMismatchFlags += 1;
      if (signal.type === "MISSING_INTEGRITY")
        summary.missingIntegrityFlags += 1;
      if (signal.type === "WEAK_INTEGRITY") summary.weakIntegrityFlags += 1;
    }
  }

  return summary;
}

// ─── Generic helpers ──────────────────────────────────────────────────────────

function addSignal(signalsByPackage, key, signal) {
  if (!signalsByPackage[key]) signalsByPackage[key] = [];

  // Deduplicate same type/title from multiple scanners.
  const exists = signalsByPackage[key].some(
    (existing) =>
      existing.type === signal.type && existing.title === signal.title,
  );
  if (!exists) signalsByPackage[key].push(signal);
}

function packageKey(name, version) {
  return `${name}@${version}`;
}

function encodePackageName(name) {
  return encodeURIComponent(name).replace(/%2F/g, "%2f");
}

function isRecentDate(date, thresholdDays) {
  const diffMs = Date.now() - date.getTime();
  return diffMs >= 0 && diffMs <= thresholdDays * 24 * 60 * 60 * 1000;
}

function daysAgo(date) {
  return Math.max(
    0,
    Math.floor((Date.now() - date.getTime()) / (24 * 60 * 60 * 1000)),
  );
}

function truncate(value, maxLen) {
  if (!value) return "";
  return value.length <= maxLen ? value : `${value.slice(0, maxLen - 1)}...`;
}

async function runWithConcurrency(items, limit, worker) {
  const queue = [...items];

  const runners = Array.from({ length: Math.max(1, limit) }, async () => {
    while (queue.length > 0) {
      const next = queue.shift();
      if (!next) return;
      await worker(next);
    }
  });

  await Promise.all(runners);
}
