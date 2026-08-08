const fs = require("fs");
const path = require("path");
const { runAudit } = require("./dependency/runAudit");
const { parseProject } = require("./component/parseProject");
const extractDependencyUsage = require("./dependency/extractDependencyUsage");
const extractComponents = require("./component/extractComponents");
const buildComponentGraph = require("./component/buildComponentGraph");
const extractSinks = require("./sinks/extractSinks");
const computeReachability = require("./reachability/computeReachability");
const { buildReport } = require("./report/generateReport");

const defaultDependencies = {
  auditRunner: runAudit,
  projectParser: parseProject,
  dependencyExtractor: extractDependencyUsage,
  componentExtractor: extractComponents,
  graphBuilder: buildComponentGraph,
  sinkExtractor: extractSinks,
  reachabilityAnalyzer: computeReachability,
  reportBuilder: buildReport,
  logger: null,
  clock: () => new Date(),
};

function projectError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

async function scanProject(projectPath, config = {}, dependencies = {}) {
  const deps = { ...defaultDependencies, ...dependencies };
  const absolutePath = path.resolve(projectPath);
  if (!fs.existsSync(absolutePath)) throw projectError(`Project not found: ${absolutePath}`, "PROJECT_NOT_FOUND");
  if (!fs.statSync(absolutePath).isDirectory()) throw projectError(`Project path is not a directory: ${absolutePath}`, "INVALID_PROJECT_PATH");

  const progress = (stage, message, data = {}) => deps.logger?.({ stage, message, ...data });
  const vulnerablePackages = await deps.auditRunner(absolutePath, config);
  progress("audit", "Dependency audit completed", { count: vulnerablePackages.size });
  const parsedFiles = await deps.projectParser(absolutePath, config);
  progress("parse", "Source parsing completed", { count: parsedFiles.length });
  const dependencyUsages = await deps.dependencyExtractor(parsedFiles, vulnerablePackages, config);
  progress("dependencies", "Dependency usage extraction completed", { count: dependencyUsages.length });
  const components = await deps.componentExtractor(parsedFiles, config);
  progress("components", "Component extraction completed", { count: components.length });
  const sinks = await deps.sinkExtractor(parsedFiles, config);
  progress("sinks", "Sink extraction completed", { count: sinks.length });
  const graph = await deps.graphBuilder(components, config);
  progress("graph", "Component graph completed", { nodes: graph.size, edges: graph.edgeCount, roots: graph.roots().length });
  const findings = await deps.reachabilityAnalyzer(dependencyUsages, components, sinks, graph, config);
  progress("reachability", "Reachability analysis completed", { count: findings.length });
  const diagnostics = findings.diagnostics ?? [];
  const scannedAt = deps.clock().toISOString();
  const report = await deps.reportBuilder(absolutePath, vulnerablePackages, parsedFiles, components, graph, sinks, findings, { scannedAt, config, diagnostics });

  return { projectPath: absolutePath, vulnerablePackages, parsedFiles, dependencyUsages, components, sinks, graph, findings, diagnostics, report };
}

module.exports = { scanProject, defaultDependencies };
