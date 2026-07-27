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

The existing reachability ordering remains the default. `--sort risk` is accepted for forward compatibility with the risk-scoring phase; until scores are available it falls back to reachability ordering.

Project defaults can be stored in `reactreach.config.json`:

```json
{
  "sinks": ["eval", "inner-html", "location"],
  "excludeSinks": [],
  "minSinkPriority": 50,
  "sinkPriorities": {
    "location": 90
  },
  "sort": "sink-priority"
}
```

CLI arguments override the project configuration, which overrides built-in defaults. Use `--config <file>` to select a different JSON file. Invalid or conflicting sink IDs fail before the scan begins.

Each detected sink now includes `ruleId`, `category`, `priority`, and `confidence`. Reachability findings expose these as `sinkRuleId`, `sinkCategory`, `sinkPriority`, and `confidence`, while retaining all existing fields.

## Adding a sink rule

Sink rules are modules under `src/sinks/rules` and are registered in `src/sinks/registry.js`. A rule declares its metadata, Babel visitor node type, matcher, and the AST value whose referenced identifiers should be tracked:

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

The central extractor does not need to be changed when another rule is added to the registry.

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

# Licence

This project is intended for academic research purposes.
