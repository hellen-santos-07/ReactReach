const { execFileSync } = require("node:child_process");

/**
 * @typedef {object} VulnerablePackage
 * @property {string} name - Package name reported by npm audit.
 * @property {string} severity - Normalized npm severity.
 * @property {boolean} isDirect - Whether the package is a direct dependency.
 * @property {Array<unknown>} via - Advisory or dependency-chain entries.
 * @property {string[]} effects - Packages affected through this dependency.
 * @property {string|null} range - Vulnerable version range.
 * @property {string[]} nodes - Installed dependency paths affected.
 * @property {boolean|object} fixAvailable - npm's available-fix description.
 */

function auditError(message, cause) {
  const error = new Error(message);
  error.code = "AUDIT_FAILED";
  if (cause) error.cause = cause;
  return error;
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function auditFailureDetail(error) {
  return error.summary || error.message || error.code || "npm audit returned an error";
}

function validateAuditDocument(auditData) {
  if (!isRecord(auditData)) throw auditError("Dependency audit returned an invalid document");
  if (auditData.error) throw auditError(`Dependency audit failed: ${auditFailureDetail(auditData.error)}`);
  if (!isRecord(auditData.vulnerabilities)) {
    throw auditError("Dependency audit document does not contain a vulnerabilities object");
  }
  return auditData;
}

function parseAuditOutput(output) {
  let auditData;
  try {
    auditData = JSON.parse(String(output));
  } catch (cause) {
    throw auditError(`Dependency audit returned invalid JSON: ${cause.message}`, cause);
  }
  return validateAuditDocument(auditData);
}

/**
 * Run `npm audit` for a project and normalize its vulnerable packages.
 *
 * @param {string} projectPath - Project directory in which npm audit is run.
 * @param {object} [_config={}] - Reserved configuration argument.
 * @param {object} [dependencies={}] - Optional process dependencies for testing.
 * @param {Function} [dependencies.auditExecutor] - Replacement for `execFileSync`.
 * @param {string} [dependencies.npmCommand] - npm executable name or path.
 * @returns {Map<string, VulnerablePackage>} Vulnerabilities keyed by package name.
 * @throws {Error} An error with code `AUDIT_FAILED` when audit execution or parsing fails.
 */
function runAudit(projectPath, _config = {}, dependencies = {}) {
  const executor = dependencies.auditExecutor || execFileSync;
  const npmCommand = dependencies.npmCommand || (process.platform === "win32" ? "npm.cmd" : "npm");
  let auditData;
  try {
    const result = executor(npmCommand, ["audit", "--json"], {
      cwd: projectPath,
      encoding: "utf8",
      stdio: "pipe",
    });

    auditData = parseAuditOutput(result);
  } catch (cause) {
    if (cause.code === "AUDIT_FAILED") throw cause;
    const stdout = cause.stdout === undefined || cause.stdout === null ? "" : String(cause.stdout).trim();
    if (stdout) auditData = parseAuditOutput(stdout);
    else throw auditError(`Unable to execute npm audit: ${cause.message}`, cause);
  }

  return extractVulnerablePackages(auditData);
}

/**
 * Normalize the vulnerability entries in an npm audit document.
 *
 * @param {object} auditData - Parsed npm audit JSON document.
 * @returns {Map<string, VulnerablePackage>} Vulnerabilities keyed by package name.
 */
function extractVulnerablePackages(auditData) {
  const vulnerable = new Map();

  if (!auditData || !auditData.vulnerabilities) {
    return vulnerable;
  }

  for (const [pkgName, info] of Object.entries(auditData.vulnerabilities)) {
    vulnerable.set(pkgName, {
      name: pkgName,
      severity: info.severity || "unknown",
      isDirect: !!info.isDirect,
      via: info.via || [],
      effects: info.effects || [],
      range: info.range || null,
      nodes: info.nodes || [],
      fixAvailable: info.fixAvailable || false,
    });
  }

  return vulnerable;
}

module.exports = {
  runAudit,
  extractVulnerablePackages,
  parseAuditOutput,
  auditError,
  validateAuditDocument,
};
