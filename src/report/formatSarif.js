const fs = require("node:fs");
const { version: REACTREACH_VERSION } = require("../../package.json");
const { relativeReportPath } = require("./buildReport");

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

function toRuleId(finding) {
  const { reachability, propagationType } = finding;
  if (reachability === "CRITICAL") return "RR-CRITICAL";
  if (reachability === "HIGH") {
    return propagationType === "inter-component"
      ? "RR-HIGH-INTER"
      : "RR-HIGH-INTRA";
  }
  if (reachability === "MEDIUM") return "RR-MEDIUM";
  if (reachability === "LOW") return "RR-LOW";
  return "RR-NONE";
}

function toSarifLevel(reachability) {
  if (reachability === "CRITICAL" || reachability === "HIGH") return "error";
  if (reachability === "MEDIUM") return "warning";
  if (reachability === "LOW") return "note";
  return "none";
}

function toFileUri(absolutePath) {
  const normalized = absolutePath.replace(/\\/g, "/");
  return /^[A-Za-z]:\//.test(normalized)
    ? `file:///${normalized}`
    : `file://${normalized}`;
}

/**
 * Build a SARIF 2.1.0 document from a structured ReactReach report.
 *
 * @param {object} report - Output of `buildReport`.
 * @returns {object} SARIF document ready for JSON serialization.
 */
function formatSarifReport(report) {
  const { projectPath, scannedAt, analyzedFiles = [], findings } = report;
  const projectDir = projectPath.replace(/\\/g, "/").replace(/\/?$/, "/");

  const artifacts = analyzedFiles.map((filePath) => ({
    location: {
      uri: relativeReportPath(filePath, projectDir),
      uriBaseId: "%SRCROOT%",
    },
  }));

  const ruleIndexMap = new Map(SARIF_RULES.map((rule, index) => [rule.id, index]));
  const results = findings.map((finding) => {
    const ruleId = toRuleId(finding);
    const ruleIndex = ruleIndexMap.get(ruleId) ?? -1;
    const level = toSarifLevel(finding.reachability);
    const isInterComponent = finding.propagationType === "inter-component";
    const sinkFile = finding.sinkFilePath ?? finding.filePath;
    const componentLabel = isInterComponent
      ? `${finding.component} -> ${finding.childComponent}`
      : (finding.component ?? "(unknown)");
    const message = [
      `[${finding.reachability}] Package '${finding.packageName}' (audit severity: ${finding.auditSeverity ?? "unknown"}): ${finding.reason}.`,
      finding.sinkType ? `Sink: ${finding.sinkType}.` : "",
      finding.taintedPath?.length ? `Taint path: ${finding.taintedPath.join(" -> ")}.` : "",
    ]
      .filter(Boolean)
      .join(" ");

    const physicalLocation = {
      artifactLocation: {
        uri: relativeReportPath(sinkFile, projectDir),
        uriBaseId: "%SRCROOT%",
      },
    };
    if (finding.sinkLoc?.start) {
      physicalLocation.region = {
        startLine: finding.sinkLoc.start.line,
        startColumn: finding.sinkLoc.start.column + 1,
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
        packageName: finding.packageName,
        reachability: finding.reachability,
        auditSeverity: finding.auditSeverity ?? "unknown",
        reasonCode: finding.reasonCode ?? null,
        component: finding.component ?? null,
        childComponent: finding.childComponent ?? null,
        sinkType: finding.sinkType ?? null,
        sinkRuleId: finding.sinkRuleId ?? null,
        sinkCategory: finding.sinkCategory ?? null,
        sinkPriority: finding.sinkPriority ?? null,
        confidence: finding.confidence ?? null,
        taintedPath: finding.taintedPath ?? [],
        propagationType: finding.propagationType ?? "intra-component",
        componentPath: finding.componentPath ?? null,
        propagationPath: finding.propagationPath ?? null,
        componentResolutionConfidence: finding.componentResolutionConfidence ?? null,
      },
    };

    if (isInterComponent && finding.filePath !== sinkFile) {
      result.relatedLocations = [
        {
          id: 1,
          message: {
            text: `Vulnerable dependency '${finding.packageName}' imported here`,
          },
          physicalLocation: {
            artifactLocation: {
              uri: relativeReportPath(finding.filePath, projectDir),
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
            version: REACTREACH_VERSION,
            informationUri: "https://github.com/hellen-santos-07/ReactReach",
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
          vulnerablePackages: (report.packages ?? []).map((entry) => ({
            name: entry.name,
            severity: entry.severity,
            isDirect: entry.isDirect,
            range: entry.range,
            fixAvailable: entry.fixAvailable,
          })),
        },
      },
    ],
  };
}

/**
 * Write a structured ReactReach report as SARIF 2.1.0 JSON.
 *
 * @param {object} report - Output of `buildReport`.
 * @param {string} outPath - Destination file path.
 * @returns {void}
 */
function saveSarifReport(report, outPath) {
  fs.writeFileSync(
    outPath,
    JSON.stringify(formatSarifReport(report), null, 2),
    "utf8",
  );
}

module.exports = { formatSarifReport, saveSarifReport };
