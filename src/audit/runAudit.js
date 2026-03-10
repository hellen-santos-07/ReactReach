const { execSync } = require("child_process");
const path = require("path");

function runAudit(projectPath) {

  try {

    const result = execSync(
      "npm audit --json",
      {
        cwd: projectPath,
        encoding: "utf8",
        stdio: "pipe"
      }
    );

    const auditData = JSON.parse(result);

    return auditData;

  } catch (error) {

    if (error.stdout) {
      return JSON.parse(error.stdout);
    }

    throw error;
  }
}

module.exports = runAudit;