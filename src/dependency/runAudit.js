const { execSync } = require("child_process");

function runAudit(projectPath) {
  try {
    const result = execSync("npm audit --json", {
      cwd: projectPath,
      encoding: "utf8",
      stdio: "pipe"
    });

    return JSON.parse(result);
  } catch (error) {
    if (error.stdout) {
      return JSON.parse(error.stdout);
    }
    throw error;
  }
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
      fixAvailable: info.fixAvailable || false
    });
  }

  return vulnerable;
}

module.exports = {
  runAudit,
  extractVulnerablePackages
};