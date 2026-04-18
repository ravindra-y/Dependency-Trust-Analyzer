import licenseChecker from "license-checker";
import path from "path";
import fs from "fs";

// This module normalizes license-checker output into a predictable
// dependency list used by the rest of the CLI pipeline.

// ─── Types (JSDoc) ────────────────────────────────────────────────────────────

/**
 * @typedef {Object} ScannedPackage
 * @property {string} name       - Package name  (e.g. "lodash")
 * @property {string} version    - Package version (e.g. "4.17.21")
 * @property {string} license    - SPDX license identifier (e.g. "MIT")
 * @property {string|null} repository - Repository URL if available
 */

// ─── Validation ───────────────────────────────────────────────────────────────

/**
 * Resolves a scan target to a project root directory.
 * Accepts either a directory path or a direct path to package.json.
 *
 * @param {string} projectPath - Relative or absolute scan target.
 * @returns {string} Absolute path to the project root directory.
 */
export function resolveProjectRoot(projectPath = ".") {
  const resolvedPath = path.resolve(projectPath);

  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Path not found: "${resolvedPath}"`);
  }

  const stat = fs.statSync(resolvedPath);
  if (stat.isDirectory()) return resolvedPath;

  if (
    stat.isFile() &&
    path.basename(resolvedPath).toLowerCase() === "package.json"
  ) {
    return path.dirname(resolvedPath);
  }

  throw new Error(
    `Path must be a project directory or package.json file: "${resolvedPath}"`,
  );
}

/**
 * Validates that the given path is a directory containing a package.json.
 * Throws a descriptive error if not satisfied.
 * @param {string} resolvedPath - Absolute path to the project root.
 */
function assertValidProject(resolvedPath) {
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Path not found: "${resolvedPath}"`);
  }

  if (!fs.statSync(resolvedPath).isDirectory()) {
    throw new Error(`Path is not a directory: "${resolvedPath}"`);
  }

  const pkgJson = path.join(resolvedPath, "package.json");
  if (!fs.existsSync(pkgJson)) {
    throw new Error(
      `No package.json found at "${resolvedPath}".\n` +
        "  Make sure you are pointing to the root of a Node.js project.",
    );
  }
}

/**
 * Reads and parses project package.json.
 * @param {string} projectRoot - Absolute path to the project root.
 * @returns {{ name?: string, version?: string, dependencies?: Object, optionalDependencies?: Object }}
 */
function readProjectManifest(projectRoot) {
  const pkgJson = path.join(projectRoot, "package.json");

  try {
    return JSON.parse(fs.readFileSync(pkgJson, "utf8"));
  } catch {
    throw new Error(
      `Could not parse package.json at "${pkgJson}". Fix JSON syntax and try again.`,
    );
  }
}

/**
 * Converts a dependency range into a best-effort version string.
 * Example: ^4.17.21 -> 4.17.21
 * @param {string} spec
 * @returns {string}
 */
function normalizeVersionSpec(spec) {
  const raw = String(spec || "").trim();
  if (!raw) return "unknown";

  const exactMatch = raw.match(/\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/);
  return exactMatch ? exactMatch[0] : raw;
}

/**
 * Builds package rows from declared dependencies when node_modules is missing.
 * @param {{ dependencies?: Object, optionalDependencies?: Object }} manifest
 * @returns {ScannedPackage[]}
 */
function buildDeclaredDependencyFallback(manifest) {
  // If node_modules is unavailable, use declared dependencies so the
  // scan can still provide a useful report instead of failing early.
  const merged = new Map();
  const sections = [manifest.dependencies, manifest.optionalDependencies];

  for (const section of sections) {
    if (!section || typeof section !== "object") continue;
    for (const [name, versionSpec] of Object.entries(section)) {
      if (!merged.has(name)) merged.set(name, versionSpec);
    }
  }

  return [...merged.entries()].map(([name, versionSpec]) => ({
    name,
    version: normalizeVersionSpec(versionSpec),
    license: "Unknown",
    repository: null,
  }));
}

/**
 * Returns true when the scanned package row represents the project itself.
 * @param {ScannedPackage} pkg
 * @param {{ name?: string, version?: string }} manifest
 * @returns {boolean}
 */
function isRootProjectPackage(pkg, manifest) {
  if (!manifest?.name) return false;
  if (pkg.name !== manifest.name) return false;
  if (!manifest.version) return true;
  return pkg.version === String(manifest.version);
}

// ─── Normalizer ───────────────────────────────────────────────────────────────

/**
 * Parses the raw license-checker output map into a clean, structured array.
 *
 * license-checker keys look like:  "lodash@4.17.21"
 * Each value is an object with fields: licenses, repository, ...
 *
 * @param {Object} raw - Raw map returned by license-checker.
 * @returns {ScannedPackage[]}
 */
function normalize(raw) {
  return Object.entries(raw).map(([key, info]) => {
    // Split on the LAST "@" so scoped packages (@scope/name@x.y.z) work correctly
    const atIndex = key.lastIndexOf("@");
    const name = atIndex > 0 ? key.slice(0, atIndex) : key;
    const version = atIndex > 0 ? key.slice(atIndex + 1) : "unknown";

    // license-checker may return a string or an array; normalise to a string
    const license = Array.isArray(info.licenses)
      ? info.licenses.join(", ")
      : info.licenses || "Unknown";

    return {
      name,
      version,
      license,
      repository: info.repository ?? null,
    };
  });
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Scans the dependencies of a Node.js project and returns structured license data.
 *
 * @param {string} [projectPath='.'] - Relative or absolute path to the project root.
 * @returns {Promise<ScannedPackage[]>} Sorted array of scanned package objects.
 *
 * @throws {Error} If the path is invalid, has no package.json, or the scan fails.
 *
 * @example
 * const packages = await scanLicenses('./my-project');
 * // [
 * //   { name: 'lodash', version: '4.17.21', license: 'MIT', repository: '...' },
 * //   ...
 * // ]
 */
export async function scanLicenses(projectPath = ".") {
  // Parse manifest first so fallback paths can reuse it if needed.
  const resolvedPath = resolveProjectRoot(projectPath);
  const manifest = readProjectManifest(resolvedPath);

  // ── Pre-flight checks ──────────────────────────────────────────────────────
  assertValidProject(resolvedPath);

  // ── Run license-checker ────────────────────────────────────────────────────
  const raw = await new Promise((resolve, reject) => {
    licenseChecker.init(
      {
        start: resolvedPath,
        production: true, // skip devDependencies
        excludePrivatePackages: true,
        failOnUnlicensedPackages: false,
      },
      (err, packages) => {
        if (err) {
          // Provide a cleaner error message than the library's default
          const msg = err.message || String(err);
          if (msg.includes("No packages found")) {
            // Treat this as an empty result so fallback logic can decide
            // whether declared dependencies should be returned.
            return resolve({});
          }
          return reject(new Error(`License scan failed: ${msg}`));
        }
        resolve(packages);
      },
    );
  });

  // ── Normalize and sort alphabetically by package name ─────────────────────
  const packages = normalize(raw).filter(
    // Ignore the root project row when license-checker reports it.
    (pkg) => !isRootProjectPackage(pkg, manifest),
  );

  if (packages.length === 0) {
    // Fallback mode: report declared dependencies with unknown licenses.
    // This keeps scan output useful before npm install has been run.
    const declaredOnly = buildDeclaredDependencyFallback(manifest);
    if (declaredOnly.length > 0) {
      declaredOnly.sort((a, b) => a.name.localeCompare(b.name));
      return declaredOnly;
    }

    throw new Error(
      `No dependencies found in "${path.join(resolvedPath, "package.json")}".\n` +
        "  Add dependencies (or run npm install) before scanning.",
    );
  }

  packages.sort((a, b) => a.name.localeCompare(b.name));

  return packages;
}
