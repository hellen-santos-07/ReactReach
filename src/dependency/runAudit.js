const { execSync } = require("child_process");

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
function runAudit(projectPath) {
  let auditData;
  try {
    const result = execSync("npm audit --json", {
      cwd: projectPath,
      encoding: "utf8",
      stdio: "pipe",
    });

    auditData = JSON.parse(result);
  } catch (error) {
    if (error.stdout) {
      auditData = JSON.parse(error.stdout);
    } else {
      throw error;
    }
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
};
