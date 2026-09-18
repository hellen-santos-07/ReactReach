const fs = require("node:fs");
const { buildReport } = require("./buildReport");
const { printSummaryTable } = require("./formatConsole");
const { formatSarifReport, saveSarifReport } = require("./formatSarif");

/**
 * Write a structured ReactReach report as JSON.
 *
 * @param {object} report - Output of `buildReport`.
 * @param {string} outPath - Destination file path.
 * @returns {void}
 */
function saveReport(report, outPath) {
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2), "utf8");
}

// Compatibility facade retained for the existing CLI and package subpath API.
module.exports = {
  buildReport,
  printSummaryTable,
  saveReport,
  saveSarifReport,
  formatSarifReport,
};
