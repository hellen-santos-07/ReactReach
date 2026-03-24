#!/usr/bin/env node

const { Command } = require("commander");
const path = require("path");
const fs = require("fs");

const { runAudit, extractVulnerablePackages } = require("./dependency/runAudit");
const { parseProject } = require("./component/parseProject");
const extractDependencyUsage = require("./dependency/extractDependencyUsage");
const extractComponents = require("./ast/extractComponents");
const extractSinks = require("./sinks/extractSinks");
const computeReachability = require("./reachability/computeReachability");

const program = new Command();

program
  .name("reactreach")
  .description("React dependency vulnerability reachability analyser")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a React project for dependency vulnerability reachability")
  .argument("<project>", "path to the React project")
  .action((project) => {
    const projectPath = path.resolve(project);

    if (!fs.existsSync(projectPath)) {
      console.error("Project not found:", projectPath);
      process.exit(1);
    }

    console.log("ReactReach scanning project:");
    console.log(projectPath);

    const auditData = runAudit(projectPath);
    const vulnerablePackages = extractVulnerablePackages(auditData);

    console.log(`\n[1] Vulnerable packages found: ${vulnerablePackages.size}`);

    const parsedFiles = parseProject(projectPath);
    console.log(`[2] Source files parsed: ${parsedFiles.length}`);

    const dependencyUsages = extractDependencyUsage(parsedFiles, vulnerablePackages);
    console.log(`[3] Vulnerable dependency usages found: ${dependencyUsages.length}`);

    const components = extractComponents(parsedFiles);
    console.log(`[4] React components found: ${components.length}`);

    const sinks = extractSinks(parsedFiles);
    console.log(`[5] Security sinks found: ${sinks.length}`);

    const findings = computeReachability(dependencyUsages, components, sinks);
    console.log(`[6] Reachability findings: ${findings.length}`);

    console.log("\n=== Findings ===");
    console.log(JSON.stringify(findings, null, 2));
  });

program.parse(process.argv);