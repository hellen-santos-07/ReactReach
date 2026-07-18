#!/usr/bin/env node

const { Command } = require("commander");
const path = require("path");
const { scanProject } = require("./scanProject");
const { printSummaryTable, saveReport, saveSarifReport } = require("./report/generateReport");

const program = new Command();
program.name("reactreach").description("React dependency vulnerability reachability analyser").version("0.1.0");

function consoleProgress(event) {
  const labels = {
    audit: `[1] Vulnerable packages found: ${event.count}`,
    parse: `[2] Source files parsed: ${event.count}`,
    dependencies: `[3a] Vulnerable dependency usages found: ${event.count}`,
    components: `[3b] React components found: ${event.count}`,
    sinks: `[3c] Security sinks found: ${event.count}`,
    graph: `[4] Component Graph (CoG): ${event.nodes} nodes, ${event.edges} edges, ${event.roots} root(s)`,
    reachability: `[5] Reachability findings: ${event.count}`,
  };
  if (labels[event.stage]) console.log(labels[event.stage]);
}

function resolveOutput(projectPath, filePath) {
  if (path.isAbsolute(filePath) || /^\.{1,2}[\\/]/.test(filePath)) return path.resolve(filePath);
  return path.join(projectPath, filePath);
}

program.command("scan")
  .description("Scan a React project for dependency vulnerability reachability")
  .argument("<project>", "path to the React project")
  .option("-o, --output <file>", "write full results to a JSON file")
  .option("--sarif <file>", "write a SARIF 2.1.0 report to a file (.sarif)")
  .option("--json", "print raw JSON instead of the summary table")
  .action(async (project, options) => {
    const projectPath = path.resolve(project);
    console.log("ReactReach scanning project:");
    console.log(projectPath);
    const { findings, report } = await scanProject(projectPath, {}, { logger: consoleProgress });
    if (options.json) {
      console.log("\n=== Findings (JSON) ===");
      console.log(JSON.stringify(findings, null, 2));
    } else printSummaryTable(findings, projectPath + "/");
    if (options.output) {
      const outPath = resolveOutput(projectPath, options.output);
      saveReport(report, outPath);
      console.log(`\nJSON report saved to: ${outPath}`);
    }
    if (options.sarif) {
      const outPath = resolveOutput(projectPath, options.sarif);
      saveSarifReport(report, outPath);
      console.log(`\nSARIF report saved to: ${outPath}`);
    }
  });

async function main(argv = process.argv) {
  try {
    await program.parseAsync(argv);
  } catch (error) {
    console.error(error.message);
    process.exitCode = error.code === "PROJECT_NOT_FOUND" || error.code === "INVALID_PROJECT_PATH" ? 2 : 1;
  }
}

if (require.main === module) main();

module.exports = { program, resolveOutput, consoleProgress, main };
