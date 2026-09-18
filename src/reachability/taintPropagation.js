const t = require("@babel/types");

const REACT_HOOKS = new Set([
  "useState",
  "useMemo",
  "useCallback",
  "useReducer",
]);

function collectPathBindings(nodePath) {
  const bindings = new Set();
  function collect(path) {
    if (!path.isIdentifier() || !path.isReferencedIdentifier()) return;
    const binding = path.scope.getBinding(path.node.name);
    if (binding) bindings.add(binding);
  }
  collect(nodePath);
  if (nodePath.traverse) nodePath.traverse({ Identifier: collect });
  return bindings;
}

/**
 * Determine whether an AST path references a binding already marked as tainted.
 *
 * @param {object} nodePath - Babel path to inspect.
 * @param {Set<object>} taintedBindings - Tainted Babel binding objects.
 * @returns {boolean} Whether at least one referenced binding is tainted.
 */
function referencesTaint(nodePath, taintedBindings) {
  return [...collectPathBindings(nodePath)].some((binding) => taintedBindings.has(binding));
}

function addPatternBindings(patternPath, taintedBindings) {
  let changed = false;
  for (const name of Object.keys(t.getBindingIdentifiers(patternPath.node))) {
    const binding = patternPath.scope.getBinding(name);
    if (binding && !taintedBindings.has(binding)) {
      taintedBindings.add(binding);
      changed = true;
    }
  }
  return changed;
}

function getHookName(callNode) {
  const callee = callNode.callee;
  if (t.isIdentifier(callee) && REACT_HOOKS.has(callee.name)) {
    return callee.name;
  }
  if (
    t.isMemberExpression(callee) &&
    t.isIdentifier(callee.object) &&
    callee.object.name === "React" &&
    t.isIdentifier(callee.property) &&
    REACT_HOOKS.has(callee.property.name)
  ) {
    return callee.property.name;
  }
  return null;
}

function collectSetterBindings(bodyPath) {
  const setterToState = new Map();
  bodyPath.traverse({
    VariableDeclarator(path) {
      if (!t.isArrayPattern(path.node.id) || !t.isCallExpression(path.node.init) || getHookName(path.node.init) !== "useState") return;
      const [stateNode, setterNode] = path.node.id.elements;
      if (!t.isIdentifier(stateNode) || !t.isIdentifier(setterNode)) return;
      const stateBinding = path.scope.getBinding(stateNode.name);
      const setterBinding = path.scope.getBinding(setterNode.name);
      if (stateBinding && setterBinding) setterToState.set(setterBinding, stateBinding);
    },
  });
  return setterToState;
}

function propagateBindingPass(bodyPath, taintedBindings, setterToState) {
  let changed = false;
  function add(binding) {
    if (!binding || taintedBindings.has(binding)) return;
    taintedBindings.add(binding);
    changed = true;
  }
  bodyPath.traverse({
    CallExpression(path) {
      if (!t.isIdentifier(path.node.callee) || path.node.arguments.length === 0) return;
      const setterBinding = path.scope.getBinding(path.node.callee.name);
      const stateBinding = setterToState.get(setterBinding);
      const firstArgument = path.get("arguments")[0];
      if (stateBinding && firstArgument && referencesTaint(firstArgument, taintedBindings)) add(stateBinding);
    },
    VariableDeclarator(path) {
      if (!path.node.init) return;
      const initPath = path.get("init");
      const idPath = path.get("id");
      const hookName = t.isCallExpression(path.node.init) ? getHookName(path.node.init) : null;
      if (hookName === "useState") {
        const initial = initPath.get("arguments")[0];
        const stateNode = t.isArrayPattern(path.node.id) ? path.node.id.elements[0] : null;
        if (initial && t.isIdentifier(stateNode) && referencesTaint(initial, taintedBindings)) add(path.scope.getBinding(stateNode.name));
        return;
      }
      if (hookName === "useReducer") {
        const initial = initPath.get("arguments")[1];
        const stateNode = t.isArrayPattern(path.node.id) ? path.node.id.elements[0] : null;
        if (initial && t.isIdentifier(stateNode) && referencesTaint(initial, taintedBindings)) add(path.scope.getBinding(stateNode.name));
        return;
      }
      if (referencesTaint(initPath, taintedBindings) && addPatternBindings(idPath, taintedBindings)) changed = true;
    },
    AssignmentExpression(path) {
      if (!t.isIdentifier(path.node.left) || !referencesTaint(path.get("right"), taintedBindings)) return;
      add(path.scope.getBinding(path.node.left.name));
    },
  });
  return changed;
}

/**
 * Compute a bounded, monotone fixed point of tainted bindings in one component.
 *
 * @param {object} component - Extracted React component with Babel paths.
 * @param {Iterable<string>} sourceIdentifiers - Imported or prop identifiers used as taint seeds.
 * @param {object} [options={}] - Propagation controls and diagnostic sink.
 * @param {number} [options.maxIterations=100] - Maximum complete propagation passes.
 * @param {object[]} [options.diagnostics] - Mutable collection for non-fatal diagnostics.
 * @returns {{bindings: Set<object>, sourceBindings: Set<object>, names: Set<string>}} Taint state at convergence or at the configured limit.
 */
function computeTaintedBindings(component, sourceIdentifiers, options = {}) {
  const taintedBindings = new Set();
  const sourceBindings = new Set();
  const bodyPath = component.bodyPath;
  if (!bodyPath) return { bindings: taintedBindings, sourceBindings, names: new Set(sourceIdentifiers) };
  for (const identifier of sourceIdentifiers) {
    const binding = component.componentPath.scope.getBinding(identifier);
    if (binding) {
      taintedBindings.add(binding);
      sourceBindings.add(binding);
    }
  }
  const setterToState = collectSetterBindings(bodyPath);
  const maxIterations = options.maxIterations ?? 100;
  let changed = true;
  let iterations = 0;
  while (changed && iterations < maxIterations) {
    changed = propagateBindingPass(bodyPath, taintedBindings, setterToState);
    iterations++;
  }
  if (changed) {
    options.diagnostics?.push({
      code: "TAINT_ITERATION_LIMIT",
      filePath: component.filePath,
      component: component.name,
      maxIterations,
      message: `Taint propagation reached the ${maxIterations}-iteration limit`,
    });
  }
  return {
    bindings: taintedBindings,
    sourceBindings,
    names: new Set([...taintedBindings].map((binding) => binding.identifier.name)),
  };
}

module.exports = { computeTaintedBindings, referencesTaint };
