/**
 * Convert a report file path to project-relative, forward-slash form.
 *
 * @param {string} filePath - File path recorded by the analyser.
 * @param {string} projectPath - Root path of the analysed project.
 * @returns {string} Project-relative path when the file is inside the project.
 */
function relativeReportPath(filePath, projectPath) {
  const normalizedFile = (filePath ?? "").replace(/\\/g, "/");
  const normalizedProject = projectPath.replace(/\\/g, "/").replace(/\/?$/, "/");
  return normalizedFile.startsWith(normalizedProject)
    ? normalizedFile.slice(normalizedProject.length)
    : normalizedFile;
}

/**
 * Build the structured ReactReach report from the analysis-stage outputs.
 *
 * @param {string} projectPath - Root path of the analysed project.
 * @param {Map} vulnerablePackages - Normalized npm audit vulnerabilities.
 * @param {Array} parsedFiles - Parsed source files.
 * @param {Array} components - Extracted React components.
 * @param {object} graph - Component ownership graph.
 * @param {Array} sinks - Extracted security-sensitive sinks.
 * @param {Array} findings - Structural reachability findings.
 * @param {object} [options={}] - Report metadata and effective configuration.
 * @returns {object} Structured ReactReach report.
 */
function buildReport(
  projectPath,
  vulnerablePackages,
  parsedFiles,
  components,
  graph,
  sinks,
  findings,
  options = {},
) {
  return {
    projectPath,
    scannedAt: options.scannedAt ?? new Date().toISOString(),
    configuration: options.config ?? {},
    diagnostics: options.diagnostics ?? [],
    timings: options.timings ?? {},
    summary: {
      vulnerablePackages: vulnerablePackages.size,
      sourceFiles: parsedFiles.length,
      components: components.length,
      cogNodes: graph.size,
      cogEdges: graph.edgeCount,
      sinks: sinks.length,
      findings: findings.length,
    },
    packages: [...vulnerablePackages.values()],
    analyzedFiles: parsedFiles.map((file) => file.filePath),
    findings,
  };
}

module.exports = { buildReport, relativeReportPath };
