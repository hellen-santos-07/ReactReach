#!/usr/bin/env node

const { Command } = require("commander");
const path = require("path");
const { scanProject } = require("./scanProject");
const { loadConfig } = require("./config");
const { listSinkRules } = require("./sinks/registry");
const { printSummaryTable, saveReport, saveSarifReport } = require("./report/generateReport");

function parseSinkList(value) {
  const ids = value.split(",").map((id) => id.trim()).filter(Boolean);
  if (!ids.length) throw new Error("Expected at least one sink id");
  return ids;
}

function parsePriority(value) {
  const priority = Number(value);
  if (!Number.isFinite(priority)) throw new Error("Priority must be a number");
  return priority;
}

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

function createProgram(dependencies = {}) {
  const scanner = dependencies.scanProject || scanProject;
  const program = new Command();
  program.name("reactreach").description("React dependency vulnerability reachability analyser").version("0.1.0");

  program.command("list-sinks")
    .description("List available security sink rules")
    .option("--json", "print sink metadata as JSON")
    .action((options) => {
      const rules = listSinkRules();
      if (options.json) return console.log(JSON.stringify(rules, null, 2));
      console.log("ID                       PRIORITY  CONFIDENCE  CATEGORY          NAME");
      for (const rule of rules) console.log(`${rule.id.padEnd(24)} ${String(rule.defaultPriority).padEnd(9)} ${String(rule.confidence).padEnd(11)} ${rule.category.padEnd(17)} ${rule.name}`);
    });

  program.command("scan")
    .description("Scan a React project for dependency vulnerability reachability")
    .argument("<project>", "path to the React project")
    .option("-o, --output <file>", "write full results to a JSON file")
    .option("--sarif <file>", "write a SARIF 2.1.0 report to a file (.sarif)")
    .option("--json", "print raw JSON instead of the summary table")
    .option("--config <file>", "read configuration from a JSON file")
    .option("--sinks <ids>", "enable only comma-separated sink ids", parseSinkList)
    .option("--exclude-sinks <ids>", "disable comma-separated sink ids", parseSinkList)
    .option("--min-sink-priority <number>", "minimum sink priority (0-100)", parsePriority)
    .option("--sort <mode>", "sort by reachability or sink-priority")
    .action(async (project, options) => {
      const projectPath = path.resolve(project);
      const sinkIds = listSinkRules().map((rule) => rule.id);
      const { config, configPath } = loadConfig(projectPath, {
        configPath: options.config,
        cliConfig: {
          sinks: options.sinks,
          excludeSinks: options.excludeSinks,
          minSinkPriority: options.minSinkPriority,
          sort: options.sort,
        },
      }, sinkIds);
      console.log("ReactReach scanning project:");
      console.log(projectPath);
      if (configPath) console.log(`Configuration: ${configPath}`);
      const { findings, report } = await scanner(projectPath, config, { logger: consoleProgress });
      if (options.json) {
        console.log("\n=== Findings (JSON) ===");
        console.log(JSON.stringify(findings, null, 2));
      } else printSummaryTable(findings, projectPath + "/", { sort: config.sort });
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
  return program;
}

const program = createProgram();
async function main(argv = process.argv) {
  try { await program.parseAsync(argv); }
  catch (error) {
    console.error(error.message);
    process.exitCode = ["PROJECT_NOT_FOUND", "INVALID_PROJECT_PATH", "INVALID_CONFIG"].includes(error.code) ? 2 : 1;
  }
}
if (require.main === module) main();

module.exports = { program, createProgram, resolveOutput, consoleProgress, parseSinkList, parsePriority, main };
