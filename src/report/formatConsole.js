const { relativeReportPath } = require("./buildReport");

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };
const SEVERITY_COLOUR = {
  CRITICAL: "\x1b[31m",
  HIGH: "\x1b[33m",
  MEDIUM: "\x1b[36m",
  LOW: "\x1b[90m",
  NONE: "\x1b[90m",
};
const RESET = "\x1b[0m";
const SUMMARY_WIDTHS = Object.freeze({ sev: 8, audit: 10, pkg: 20, comp: 22, sink: 28, file: 36 });

function trunc(value, maxLength) {
  if (!value) return "";
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
}

function severityRank(reachability) {
  return SEVERITY_ORDER[reachability] ?? 99;
}

function sortFindings(findings, sortMode) {
  const severitySort = (left, right) => severityRank(left.reachability) - severityRank(right.reachability);
  return [...findings].sort((left, right) => {
    if (sortMode !== "sink-priority") return severitySort(left, right);
    return (right.sinkPriority ?? -1) - (left.sinkPriority ?? -1) || severitySort(left, right);
  });
}

function formatSummaryRow(severity, audit, packageName, component, sink, file, colour = "") {
  const width = SUMMARY_WIDTHS;
  return `${colour}${severity.padEnd(width.sev)}${RESET}  ` +
    `${trunc(audit, width.audit).padEnd(width.audit)}  ` +
    `${trunc(packageName, width.pkg).padEnd(width.pkg)}  ` +
    `${trunc(component, width.comp).padEnd(width.comp)}  ` +
    `${trunc(sink, width.sink).padEnd(width.sink)}  ` +
    `${trunc(file, width.file)}`;
}

function summaryDivider() {
  const width = SUMMARY_WIDTHS;
  return "-".repeat(width.sev + width.audit + width.pkg + width.comp + width.sink + width.file + 10);
}

function findingSummaryLabels(finding, projectPath) {
  return {
    component: finding.childComponent ? `${finding.component} -> ${finding.childComponent}` : (finding.component ?? "-"),
    sink: finding.sinkType ?? "-",
    file: relativeReportPath(finding.sinkFilePath ?? finding.filePath, projectPath),
    audit: finding.auditSeverity ?? "-",
    colour: SEVERITY_COLOUR[finding.reachability] ?? "",
  };
}

function printFindingRows(findings, projectPath) {
  for (const finding of findings) {
    const labels = findingSummaryLabels(finding, projectPath);
    console.log(formatSummaryRow(
      finding.reachability,
      labels.audit,
      finding.packageName,
      labels.component,
      labels.sink,
      labels.file,
      labels.colour,
    ));
  }
}

function formatLevelSummary(findings) {
  const counts = {};
  for (const finding of findings) counts[finding.reachability] = (counts[finding.reachability] ?? 0) + 1;
  return Object.entries(counts)
    .sort(([left], [right]) => severityRank(left) - severityRank(right))
    .map(([level, count]) => `${SEVERITY_COLOUR[level]}${level}: ${count}${RESET}`)
    .join("  ");
}

/**
 * Print a colour-coded findings summary table to stdout.
 *
 * @param {Array} findings - Structural reachability findings.
 * @param {string} projectPath - Root used to render relative file paths.
 * @param {object} [options={}] - Console formatting options.
 * @param {string} [options.sort] - Optional finding sort mode.
 * @returns {void}
 */
function printSummaryTable(findings, projectPath, options = {}) {
  if (findings.length === 0) {
    console.log("\nNo reachability findings.");
    return;
  }

  const sorted = sortFindings(findings, options.sort);
  const divider = summaryDivider();
  console.log("\n=== Findings Summary ===");
  console.log(formatSummaryRow("LEVEL", "AUDIT SEV", "PACKAGE", "COMPONENT", "SINK", "FILE"));
  console.log(divider);
  printFindingRows(sorted, projectPath);
  console.log(divider);
  console.log(`\nTotal: ${findings.length}  |  ${formatLevelSummary(findings)}`);
}

module.exports = { printSummaryTable };
