#!/usr/bin/env node

const { Command } = require("commander");
const path = require("path");
const fs = require("fs");

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

    // WIP
    // audit -> ast -> sinks -> reachability -> report

  });

program.parse(process.argv);