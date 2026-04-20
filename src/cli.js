#!/usr/bin/env node

const { Command } = require("commander");
const path = require("path");
const fs = require("fs");

const { runAudit } = require("./dependency/runAudit");
const { parseProject } = require("./component/parseProject");
const extractDependencyUsage = require("./dependency/extractDependencyUsage");
const extractComponents = require("./component/extractComponents");
const buildComponentGraph = require("./component/buildComponentGraph");
const extractSinks = require("./sinks/extractSinks");
const computeReachability = require("./reachability/computeReachability");
const { buildReport, printSummaryTable, saveReport, saveSarifReport } = require("./report/generateReport");

const program = new Command();

program
  .name("reactreach")
  .description("React dependency vulnerability reachability analyser")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a React project for dependency vulnerability reachability")
  .argument("<project>", "path to the React project")
  .option("-o, --output <file>", "write full results to a JSON file")
  .option("--sarif <file>", "write a SARIF 2.1.0 report to a file (.sarif)")
  .option("--json", "print raw JSON instead of the summary table")
  .action((project, options) => {
    const projectPath = path.resolve(project);

    if (!fs.existsSync(projectPath)) {
      console.error("Project not found:", projectPath);
      process.exit(1);
    }

    console.log("ReactReach scanning project:");
    console.log(projectPath);

    // Dependency Usage Analysis
    const vulnerablePackages = runAudit(projectPath);
    console.log(`\n[1] Vulnerable packages found: ${vulnerablePackages.size}`);

    const parsedFiles = parseProject(projectPath);
    console.log(`[2] Source files parsed: ${parsedFiles.length}`);

    const dependencyUsages = extractDependencyUsage(parsedFiles, vulnerablePackages);
    console.log(`[3] Vulnerable dependency usages found: ${dependencyUsages.length}`);

    // Component Module
    const components = extractComponents(parsedFiles);
    console.log(`[4.1] React components found: ${components.length}`);

    const graph = buildComponentGraph(components);
    const roots = graph.roots();
    console.log(`[4.2] Component Graph (CoG): ${graph.size} nodes, ${graph.edgeCount} edges, ${roots.length} root(s)`);

    // Security Sinks Module
    const sinks = extractSinks(parsedFiles);
    console.log(`[5] Security sinks found: ${sinks.length}`);

    // Reachability Module
    const findings = computeReachability(dependencyUsages, components, sinks, graph);
    console.log(`[6] Reachability findings: ${findings.length}`);

    const report = buildReport(
      projectPath, vulnerablePackages, parsedFiles, components, graph, sinks, findings
    );

    if (options.json) {
      console.log("\n=== Findings (JSON) ===");
      console.log(JSON.stringify(findings, null, 2));
    } else {
      printSummaryTable(findings, projectPath + "/");
    }

    function resolveOutput(filePath) {
      if (path.isAbsolute(filePath) || /^\.{1,2}[\\/]/.test(filePath)) {
        return path.resolve(filePath);
      }
      return path.join(projectPath, filePath);
    }

    if (options.output) {
      const outPath = resolveOutput(options.output);
      saveReport(report, outPath);
      console.log(`\nJSON report saved to: ${outPath}`);
    }

    if (options.sarif) {
      const outPath = resolveOutput(options.sarif);
      saveSarifReport(report, outPath);
      console.log(`\nSARIF report saved to: ${outPath}`);
    }
  });

program.parse(process.argv);