const fs = require("fs");
const path = require("path");
const { performance } = require("node:perf_hooks");
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
  now: () => performance.now(),
};

function projectError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function roundedDuration(value) {
  return Number(Math.max(0, value).toFixed(3));
}

async function measureStage(name, timings, now, operation) {
  const startedAt = now();
  try {
    return await operation();
  } finally {
    timings[name] = roundedDuration(now() - startedAt);
  }
}

async function scanProject(projectPath, config = {}, dependencies = {}) {
  const deps = { ...defaultDependencies, ...dependencies };
  const absolutePath = path.resolve(projectPath);
  if (!fs.existsSync(absolutePath)) throw projectError(`Project not found: ${absolutePath}`, "PROJECT_NOT_FOUND");
  if (!fs.statSync(absolutePath).isDirectory()) throw projectError(`Project path is not a directory: ${absolutePath}`, "INVALID_PROJECT_PATH");

  const scanStartedAt = deps.now();
  const timings = {};
  const progress = (stage, message, data = {}) => deps.logger?.({ stage, message, ...data });
  const runStage = async (name, operation) => measureStage(name, timings, deps.now, operation);
  const vulnerablePackages = await runStage("auditMs", () => deps.auditRunner(absolutePath, config));
  progress("audit", "Dependency audit completed", { count: vulnerablePackages.size, durationMs: timings.auditMs });
  const parsedFiles = await runStage("parseMs", () => deps.projectParser(absolutePath, config));
  progress("parse", "Source parsing completed", { count: parsedFiles.length, durationMs: timings.parseMs });
  const dependencyUsages = await runStage("dependenciesMs", () => deps.dependencyExtractor(parsedFiles, vulnerablePackages, config));
  progress("dependencies", "Dependency usage extraction completed", { count: dependencyUsages.length, durationMs: timings.dependenciesMs });
  const components = await runStage("componentsMs", () => deps.componentExtractor(parsedFiles, config));
  progress("components", "Component extraction completed", { count: components.length, durationMs: timings.componentsMs });
  const sinks = await runStage("sinksMs", () => deps.sinkExtractor(parsedFiles, config));
  progress("sinks", "Sink extraction completed", { count: sinks.length, durationMs: timings.sinksMs });
  const graph = await runStage("graphMs", () => deps.graphBuilder(components, config));
  progress("graph", "Component graph completed", { nodes: graph.size, edges: graph.edgeCount, roots: graph.roots().length, durationMs: timings.graphMs });
  const findings = await runStage("reachabilityMs", () => deps.reachabilityAnalyzer(dependencyUsages, components, sinks, graph, config));
  progress("reachability", "Reachability analysis completed", { count: findings.length, durationMs: timings.reachabilityMs });
  const diagnostics = findings.diagnostics ?? [];
  const scannedAt = deps.clock().toISOString();
  timings.staticAnalysisMs = roundedDuration([
    "parseMs", "dependenciesMs", "componentsMs", "sinksMs", "graphMs", "reachabilityMs",
  ].reduce((total, key) => total + timings[key], 0));
  const report = await runStage("reportMs", () => deps.reportBuilder(
    absolutePath,
    vulnerablePackages,
    parsedFiles,
    components,
    graph,
    sinks,
    findings,
    { scannedAt, config, diagnostics, timings },
  ));
  timings.totalMs = roundedDuration(deps.now() - scanStartedAt);

  return { projectPath: absolutePath, vulnerablePackages, parsedFiles, dependencyUsages, components, sinks, graph, findings, diagnostics, timings, report };
}

module.exports = { scanProject, defaultDependencies, measureStage, roundedDuration };
