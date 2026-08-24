# ReactReach

> Prototype tool for contextual vulnerability reachability analysis in React.js applications.

ReactReach is a prototype static analysis tool developed as part of a Master's thesis in Software Engineering at the **Instituto Politécnico do Porto (ISEP)**.

The goal of ReactReach is to analyse the **contextual reachability of dependency vulnerabilities** within React.js applications. Instead of simply reporting vulnerable dependencies, the tool evaluates whether those dependencies are actually used within the application and whether their outputs can reach **security-sensitive sinks**.

---

# Research Context

Modern **Software Composition Analysis (SCA)** tools such as `npm audit` can identify vulnerable dependencies in JavaScript projects. However, these tools do not determine whether those vulnerabilities are **actually reachable or exploitable within the context of a specific application**.

In many cases, vulnerabilities reported by SCA tools may:

- Exist in dependencies that are never used
- Exist in dependencies used in non-sensitive contexts
- Not reach any security-sensitive operations

ReactReach addresses this problem by combining:

- **Dependency vulnerability data**
- **Static code analysis**
- **React source code inspection**
- **Structural reachability analysis**

The objective is to provide a **context-aware analysis** of dependency vulnerabilities in React-based applications.

---

# Contextual Model

The analysis performed by ReactReach is based on the following contextual model:
> Context = {D, C, S, R}

Where:

### D = Dependency Usage
Identifies vulnerable dependencies present in the project based on vulnerability reports.

### C = Component Location
Identifies where vulnerable dependencies are imported or used within React components.

### S = Security-Sensitive Sink
Detects operations that may introduce security risks, such as DOM injection points.

### R = Structural Reachability
Determines whether there exists a structural path between the usage of a vulnerable dependency and a security-sensitive sink within the application.

---

# How ReactReach Works

ReactReach performs a contextual analysis pipeline consisting of the following steps:

1. Extract vulnerable dependencies from `npm audit`
2. Parse React source code using Babel AST
3. Identify dependency imports and usage locations
4. Detect security-sensitive sinks in React components
5. Evaluate structural reachability between dependencies and sinks

Which enables a **context-based analysis** of dependency vulnerabilities in React applications.

---

# Installation

Clone this repository:

```bash
git clone https://github.com/hellen-santos-07/ReactReach.git
cd ReactReach
```

Install dependencies:

```bash
npm install
```

Link the CLI locally:

```bash
npm link
```

This will expose the `reactreach` command globally on your machine.

# Usage

Run ReactReach against a React project:

```bash
reactreach scan <path-to-your-project>
```
ReactReach will analyse the project and report contextual information about dependency vulnerabilities.

Use `--json` when stdout must contain only the findings JSON array. Progress and human-readable headings are suppressed in this mode. Use `--output <file>` for the complete versioned report, including configuration, diagnostics, summary, packages, findings, and timings.

The CLI uses exit code `0` for success, `1` for project/audit/parse/execution failures, and `2` for invalid configuration or sink plugins.

## Sink selection and prioritisation

List the available sink rules and their default metadata:

```bash
reactreach list-sinks
reactreach list-sinks --json
```

Select, exclude, filter, or order sinks from the command line:

```bash
reactreach scan ./app --sinks eval,inner-html
reactreach scan ./app --exclude-sinks location
reactreach scan ./app --min-sink-priority 90
reactreach scan ./app --sort sink-priority
```

The existing reachability ordering remains the default. Use `--sort sink-priority` to place findings associated with higher-priority sinks first.

Project defaults can be stored in `reactreach.config.json`:

```json
{
  "sinks": ["eval", "inner-html", "location"],
  "excludeSinks": [],
  "minSinkPriority": 50,
  "sinkPriorities": {
    "location": 90
  },
  "sort": "sink-priority",
  "maxTaintIterations": 100,
  "includeDefaultSinks": true,
  "sinkModules": []
}
```

CLI arguments override the project configuration, which overrides built-in defaults. Use `--config <file>` to select a different JSON file. Invalid or conflicting sink IDs fail before the scan begins.

Each detected sink includes `ruleId`, `category`, `priority`, and `confidence`. Reachability findings expose these as `sinkRuleId`, `sinkCategory`, `sinkPriority`, and `confidence`, while retaining all existing fields.

Findings also contain a stable `reasonCode`, allowing report consumers to identify the analysis outcome without comparing human-readable messages.

The complete report records `auditMs`, `parseMs`, `dependenciesMs`, `componentsMs`, `sinksMs`, `graphMs`, `reachabilityMs`, `reportMs`, `staticAnalysisMs`, and `totalMs`. `staticAnalysisMs` deliberately excludes `npm audit` and report serialisation so performance experiments can measure the static analysis pipeline independently of network latency.

## Structural reachability details

Local taint propagation follows Babel bindings rather than identifier text. Variables with the same name in different lexical scopes are therefore kept separate. Propagation continues until no new bindings become tainted, supporting chains of arbitrary practical length instead of a fixed number of passes.

`maxTaintIterations` is a defensive limit between 1 and 10,000. If it is reached, the scan continues and records a `TAINT_ITERATION_LIMIT` entry in the report's `diagnostics` array.

Inter-component analysis follows tainted props across multiple component boundaries. Relative imports are used to resolve rendered components before falling back to a conservative name match. Inter-component findings include:

- `componentPath`: ordered component names from the dependency usage to the sink.
- `propagationPath`: each props boundary and its resolution method.
- `componentResolutionConfidence`: 100 for same-file/import resolution and 60 when global name fallback was required.

### Reachability classification chain

Reachability outcomes are assigned by a Chain of Responsibility. `ReachabilityHandler` defines delegation through `setNext()` and `handle()`, while concrete handlers classify no binding (LOW), unused imports (NONE), components without sinks or without a proven path (MEDIUM), propagated and inter-component flows (HIGH), and direct sink flows (CRITICAL). The chain is ordered so that direct flow takes precedence over propagated flow. It is invoked for every analysis candidate, so separate sinks can still produce multiple findings for one dependency usage.

The handlers classify evidence already produced by dependency, component, sink, taint, and CoG analysis; they do not change the underlying propagation algorithm or the meaning of existing levels and reason codes.

## AST traversal architecture

Dependency usage, component extraction, and sink extraction specialise the shared `ASTWalker` Template Method. Its `walk()` operation fixes the lifecycle for every parsed file: create the result, prepare file context, optionally execute a pre-pass, execute the specialised Babel visitor, and finalise the result. The specialised walkers provide visitors and file-specific context without duplicating the orchestration skeleton.

## Quality metrics

Run the test suite, coverage, and McCabe cyclomatic complexity measurements with:

```bash
npm test
npm run test:coverage
npm run test:schema
npm run metrics:complexity
```

The complexity command analyses `src/**/*.js` by default and accepts explicit glob patterns after `--`. It counts a base path plus decision points for conditionals, non-default switch cases, loops, catch clauses, and short-circuit logical operators, and reports per-function details as JSON.

`test:schema` validates a representative complete report against `schemas/reactreach-report.schema.json` and validates the corresponding SARIF document against the official OASIS SARIF 2.1.0 Plus Errata 01 schema. The latter check retrieves the authoritative schema and therefore requires network access.

## Adding a sink rule

The built-in Strategy rules are aggregated by the local registry `src/sinks/rules/index.js`. A rule module exports one rule object or an array of rules. Each rule declares its metadata, Babel visitor node type, matcher, and the AST value whose referenced identifiers should be tracked:

```js
{
  id: "example",
  name: "Example sink",
  category: "code-execution",
  defaultPriority: 100,
  confidence: 100,
  nodeType: "CallExpression",
  match(path) { /* return true when this node is the sink */ },
  getValueNode(path) { /* return the security-sensitive argument */ }
}
```

Projects can extend or replace the built-in rule set without changing the plugin host, registry, or reachability analysis. Additional modules are declared directly in the project's single `reactreach.config.json` file:

```json
{
  "includeDefaultSinks": true,
  "sinkModules": ["./security/rules/customAlert.js"],
  "sinks": ["eval", "custom-alert"]
}
```

`includeDefaultSinks: true` retains the built-in strategies; `false` replaces them with only the rules exported by `sinkModules`. Module paths are resolved relative to `reactreach.config.json`; they must be local, relative, and remain inside its directory. Every exported rule is validated for required metadata, functions, priorities, confidence, and duplicate IDs before scanning begins. Invalid modules fail as configuration errors with exit code 2.

The built-in registry is deterministic, version-controlled with the source code, and does not use the network. Projects do not need to create a separate catalogue file.

# Input

The analysed project should contain:
- `package.json`
- `package-lock.json`
- React source code

# Project Status
> ReactReach is currently a research prototype and under active development.

The project focuses on experimentation and evaluation as part of my personal academic research.

# Author

Hellen Santos  
Master's Degree in Software Engineering  
Instituto Politécnico do Porto (ISEP)  
- Email: 1190007@isep.ipp.pt  
- GitHub: https://github.com/hellen-santos-07

# License

This project is intended for academic research purposes.
