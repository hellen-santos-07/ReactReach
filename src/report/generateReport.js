const fs = require("fs");
const path = require("path");

// Severity ordering for sort and colour
const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };
const SEVERITY_COLOUR = {
  CRITICAL: "\x1b[31m", // red
  HIGH: "\x1b[33m", // yellow
  MEDIUM: "\x1b[36m", // cyan
  LOW: "\x1b[90m", // grey
  NONE: "\x1b[90m", // grey
};
const RESET = "\x1b[0m";
const SUMMARY_WIDTHS = Object.freeze({ sev: 8, audit: 10, pkg: 20, comp: 22, sink: 28, file: 36 });

/** Truncates a string to maxLen chars, appending "…" if cut. */
function trunc(str, maxLen) {
  if (!str) return "";
  return str.length > maxLen ? str.slice(0, maxLen - 1) + "…" : str;
}

/**
 * Strips the project path prefix from an absolute file path and returns a
 * relative-style path. Normalises to forward slashes for cross-platform safety.
 */
function rel(filePath, projectPath) {
  const normFile = (filePath ?? "").replace(/\\/g, "/");
  const normProject = projectPath.replace(/\\/g, "/").replace(/\/?$/, "/");
  return normFile.startsWith(normProject)
    ? normFile.slice(normProject.length)
    : normFile;
}

/**
 * Builds the structured report object from pipeline outputs.
 *
 * @param {string}  projectPath
 * @param {Map}     vulnerablePackages: output of extractVulnerablePackages()
 * @param {Array}   parsedFiles: output of parseProject()
 * @param {Array}   components: output of extractComponents()
 * @param {object}  graph: output of buildComponentGraph()
 * @param {Array}   sinks: output of extractSinks()
 * @param {Array}   findings: output of computeReachability()
 * @returns {object} report
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
    analyzedFiles: parsedFiles.map((f) => f.filePath),
    findings,
  };
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
    file: rel(finding.sinkFilePath ?? finding.filePath, projectPath),
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
 * Prints a colour-coded findings summary table to stdout, sorted by severity.
 *
 * @param {Array}  findings
 * @param {string} projectPath  - used to compute relative file paths in the table
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

/**
 * Serialises the report object to a JSON file at outPath.
 *
 * @param {object} report   - output of buildReport()
 * @param {string} outPath  - absolute path to write to
 */
function saveReport(report, outPath) {
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2), "utf8");
}

const SARIF_RULES = [
  {
    id: "RR-CRITICAL",
    name: "CriticalDependencyReachability",
    shortDescription: {
      text: "Vulnerable dependency identifier flows directly into a security sink",
    },
    fullDescription: {
      text: "A vulnerable third-party dependency's imported identifier is passed without transformation directly to a security-sensitive sink (e.g. dangerouslySetInnerHTML, eval). This represents the highest likelihood of exploitability within the component.",
    },
    defaultConfiguration: { level: "error" },
    helpUri: "https://owasp.org/www-community/attacks/xss/",
    help: {
      text: "Replace or patch the vulnerable dependency, or sanitise its output before passing it to the sink.",
    },
    properties: { tags: ["security", "dependency", "reachability"] },
  },
  {
    id: "RR-HIGH-INTRA",
    name: "HighDependencyReachabilityIntraComponent",
    shortDescription: {
      text: "Variable derived from vulnerable dependency reaches a security sink via intra-component propagation",
    },
    fullDescription: {
      text: "Output from a vulnerable dependency is stored in a local variable or React state (via useState, useMemo, useCallback, or useReducer) and then flows into a security-sensitive sink within the same component.",
    },
    defaultConfiguration: { level: "error" },
    helpUri: "https://owasp.org/www-community/attacks/xss/",
    help: {
      text: "Replace or patch the vulnerable dependency, or sanitise its output before passing it to the sink.",
    },
    properties: { tags: ["security", "dependency", "reachability"] },
  },
  {
    id: "RR-HIGH-INTER",
    name: "HighDependencyReachabilityInterComponent",
    shortDescription: {
      text: "Tainted data from vulnerable dependency flows through a props boundary into a child component security sink",
    },
    fullDescription: {
      text: "A parent component passes tainted output from a vulnerable dependency as a prop to a child component, where that prop reaches a security-sensitive sink. The vulnerability crosses at least one component boundary.",
    },
    defaultConfiguration: { level: "error" },
    helpUri: "https://owasp.org/www-community/attacks/xss/",
    help: {
      text: "Sanitise tainted data before passing it as props, or restructure the component hierarchy to avoid the data flow reaching the sink.",
    },
    properties: {
      tags: ["security", "dependency", "reachability", "inter-component"],
    },
  },
  {
    id: "RR-MEDIUM",
    name: "MediumDependencyReachability",
    shortDescription: {
      text: "Vulnerable dependency used in a component but no structural data path to a security sink was found",
    },
    fullDescription: {
      text: "The vulnerable dependency is actively used inside a React component, but the analysis could not establish a structural data-flow path from its output to a security sink. Manual review is advised.",
    },
    defaultConfiguration: { level: "warning" },
    help: {
      text: "Review how the dependency output is used. If it influences rendering or DOM interaction, consider patching or sanitising it.",
    },
    properties: { tags: ["security", "dependency", "reachability"] },
  },
  {
    id: "RR-LOW",
    name: "LowDependencyReachability",
    shortDescription: {
      text: "Vulnerable dependency imported but no binding name could be captured",
    },
    fullDescription: {
      text: "The vulnerable dependency is imported but the analysis could not capture a binding name (e.g. dynamic import, bare side-effect import). The vulnerability may still be triggered at runtime.",
    },
    defaultConfiguration: { level: "note" },
    help: {
      text: "Review the import pattern and determine whether the vulnerable code path can be triggered.",
    },
    properties: { tags: ["security", "dependency"] },
  },
  {
    id: "RR-NONE",
    name: "DeadDependencyImport",
    shortDescription: {
      text: "Vulnerable dependency imported but its identifier is never referenced in any component",
    },
    fullDescription: {
      text: "The vulnerable dependency is imported at the module level but its bound identifier is never referenced inside any React component body. The vulnerability is structurally unreachable under the current analysis model.",
    },
    defaultConfiguration: { level: "none" },
    help: {
      text: "Remove the unused import. If the import is intentional (side-effect), evaluate whether the side effect can trigger the vulnerability.",
    },
    properties: { tags: ["security", "dependency"] },
  },
];

/** Maps a ReactReach reachability level + propagationType to a SARIF rule id. */
function toRuleId(finding) {
  const { reachability, propagationType } = finding;
  if (reachability === "CRITICAL") return "RR-CRITICAL";
  if (reachability === "HIGH")
    return propagationType === "inter-component"
      ? "RR-HIGH-INTER"
      : "RR-HIGH-INTRA";
  if (reachability === "MEDIUM") return "RR-MEDIUM";
  if (reachability === "LOW") return "RR-LOW";
  return "RR-NONE";
}

/** Maps a ReactReach reachability level to a SARIF result level. */
function toSarifLevel(reachability) {
  if (reachability === "CRITICAL" || reachability === "HIGH") return "error";
  if (reachability === "MEDIUM") return "warning";
  if (reachability === "LOW") return "note";
  return "none";
}

/**
 * Converts an absolute OS path to a file:// URI suitable for SARIF.
 * Handles both Windows (C:\path) and Unix (/path) forms.
 */
function toFileUri(absolutePath) {
  const norm = absolutePath.replace(/\\/g, "/");
  // Windows absolute path: starts with drive letter e.g. C:/
  return /^[A-Za-z]:\//.test(norm) ? `file:///${norm}` : `file://${norm}`;
}

/**
 * Builds a SARIF 2.1.0 document from a report object.
 *
 * @param {object} report - output of buildReport()
 * @returns {object} - SARIF document (plain object, serialise with JSON.stringify)
 */
function formatSarifReport(report) {
  const { projectPath, scannedAt, analyzedFiles = [], findings } = report;
  const projectDir = projectPath.replace(/\\/g, "/").replace(/\/?$/, "/");

  //artifacts: one entry per analyzed source file
  const artifacts = analyzedFiles.map((filePath) => ({
    location: {
      uri: rel(filePath, projectDir),
      uriBaseId: "%SRCROOT%",
    },
  }));

  //build a deduplicated set of rule IDs actually used so we can index them
  const usedRuleIds = [...new Set(findings.map(toRuleId))];
  // SARIF result.rule.index must match the position in tool.driver.rules
  const ruleIndexMap = new Map(SARIF_RULES.map((r, i) => [r.id, i]));

  //results
  const results = findings.map((f) => {
    const ruleId = toRuleId(f);
    const ruleIndex = ruleIndexMap.get(ruleId) ?? -1;
    const level = toSarifLevel(f.reachability);
    const isInter = f.propagationType === "inter-component";
    const sinkFile = f.sinkFilePath ?? f.filePath;

    const componentLabel = isInter
      ? `${f.component} -> ${f.childComponent}`
      : (f.component ?? "(unknown)");
    const message = [
      `[${f.reachability}] Package '${f.packageName}' (audit severity: ${f.auditSeverity ?? "unknown"}): ${f.reason}.`,
      f.sinkType ? `Sink: ${f.sinkType}.` : "",
      f.taintedPath?.length ? `Taint path: ${f.taintedPath.join(" -> ")}.` : "",
    ]
      .filter(Boolean)
      .join(" ");

    // Physical location - prefer the sink location when available
    const physicalLocation = {
      artifactLocation: {
        uri: rel(sinkFile, projectDir),
        uriBaseId: "%SRCROOT%",
      },
    };
    if (f.sinkLoc?.start) {
      physicalLocation.region = {
        startLine: f.sinkLoc.start.line,
        startColumn: f.sinkLoc.start.column + 1, // SARIF columns are 1-based
      };
    }

    const result = {
      ruleId,
      rule: { id: ruleId, index: ruleIndex },
      level,
      message: { text: message },
      locations: [
        {
          physicalLocation,
          logicalLocations: [{ name: componentLabel, kind: "function" }],
        },
      ],
      properties: {
        packageName: f.packageName,
        reachability: f.reachability,
        auditSeverity: f.auditSeverity ?? "unknown",
        reasonCode: f.reasonCode ?? null,
        component: f.component ?? null,
        childComponent: f.childComponent ?? null,
        sinkType: f.sinkType ?? null,
        sinkRuleId: f.sinkRuleId ?? null,
        sinkCategory: f.sinkCategory ?? null,
        sinkPriority: f.sinkPriority ?? null,
        confidence: f.confidence ?? null,
        taintedPath: f.taintedPath ?? [],
        propagationType: f.propagationType ?? "intra-component",
        componentPath: f.componentPath ?? null,
        propagationPath: f.propagationPath ?? null,
        componentResolutionConfidence: f.componentResolutionConfidence ?? null,
      },
    };

    // Related location: the import site (f.filePath) when different from sink site
    if (isInter && f.filePath !== sinkFile) {
      result.relatedLocations = [
        {
          id: 1,
          message: {
            text: `Vulnerable dependency '${f.packageName}' imported here`,
          },
          physicalLocation: {
            artifactLocation: {
              uri: rel(f.filePath, projectDir),
              uriBaseId: "%SRCROOT%",
            },
          },
        },
      ];
    }

    return result;
  });

  return {
    $schema:
      "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "ReactReach",
            version: "0.1.0",
            informationUri: "https://github.com/hellensantos/reactreach",
            rules: SARIF_RULES,
          },
        },
        originalUriBaseIds: {
          "%SRCROOT%": { uri: toFileUri(projectDir) },
        },
        artifacts,
        results,
        properties: {
          scannedAt,
          summary: report.summary,
          diagnostics: report.diagnostics ?? [],
          timings: report.timings ?? {},
          vulnerablePackages: (report.packages ?? []).map((p) => ({
            name: p.name,
            severity: p.severity,
            isDirect: p.isDirect,
            range: p.range,
            fixAvailable: p.fixAvailable,
          })),
        },
      },
    ],
  };
}

/**
 * Generates a SARIF report and writes it to outPath.
 *
 * @param {object} report   - output of buildReport()
 * @param {string} outPath  - absolute path to write to
 */
function saveSarifReport(report, outPath) {
  fs.writeFileSync(
    outPath,
    JSON.stringify(formatSarifReport(report), null, 2),
    "utf8",
  );
}

module.exports = {
  buildReport,
  printSummaryTable,
  saveReport,
  saveSarifReport,
  formatSarifReport,
};
