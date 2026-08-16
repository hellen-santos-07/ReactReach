const { execFileSync } = require("node:child_process");

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
 *
 * @param {*} projectPath
 * @returns { Map<string, {
 * name: string,
 * severity: string,
 * isDirect: boolean,  
 * via: Array<string>,
 * effects: Array<string>,
 * range: string | null,
 * nodes: Array<string>,
 * fixAvailable: boolean
 *  }>}
 * 
 * name: string (the name of the vulnerable package)
 * severity: string (the severity level of the vulnerability, e.g., "low", "moderate", "high", "critical")
 * isDirect: boolean (whether the vulnerable package is a direct dependency)
 * via: Array<string> (the dependency chain leading to the vulnerable package)
 * effects: Array<string> (the paths in the dependency tree that are affected by this vulnerability)
 * range: string | null (the version range of the vulnerable package)
 * nodes: Array<string> (the specific dependency paths that lead to the vulnerable package)
 * fixAvailable: boolean (whether a fix is available for this vulnerability)
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
