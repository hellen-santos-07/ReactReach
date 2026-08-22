const ASTWalker = require("../ast/ASTWalker");
const t = require("@babel/types");

const REACT_CLASS_BASES = new Set(["Component", "PureComponent"]);

function importedName(specifier) {
  if (t.isImportDefaultSpecifier(specifier)) return "default";
  if (t.isImportNamespaceSpecifier(specifier)) return "*";
  return specifier.imported.name ?? specifier.imported.value;
}

function rememberBinding(bindings, localIdentifier) {
  bindings.set(localIdentifier.name, localIdentifier);
}

function matchesRememberedBinding(path, name, bindings) {
  const rememberedIdentifier = bindings.get(name);
  if (!rememberedIdentifier) return false;
  const binding = path.scope.getBinding(name);
  return binding?.identifier === rememberedIdentifier;
}

function memberName(node) {
  if (!t.isMemberExpression(node)) return null;
  if (!node.computed && t.isIdentifier(node.property)) return node.property.name;
  if (node.computed && t.isStringLiteral(node.property)) return node.property.value;
  return null;
}

function isReactClassComponent(path, reactBindings) {
  const superClass = path.node.superClass;
  if (t.isIdentifier(superClass)) {
    return matchesRememberedBinding(path, superClass.name, reactBindings.classBases);
  }

  if (!t.isMemberExpression(superClass) || !t.isIdentifier(superClass.object)) return false;
  return REACT_CLASS_BASES.has(memberName(superClass)) &&
    matchesRememberedBinding(path, superClass.object.name, reactBindings.namespaces);
}

function isJSXReturningFunction(node) {
  if (!node || !node.body) return false;

  if (node.body.type === "JSXElement" || node.body.type === "JSXFragment") {
    return true;
  }

  if (node.body.type === "BlockStatement") {
    return node.body.body.some(
      (statement) =>
        statement.type === "ReturnStatement" &&
        statement.argument &&
        (statement.argument.type === "JSXElement" || statement.argument.type === "JSXFragment")
    );
  }

  return false;
}

function createImportVisitors(fileImports, componentImports, reactBindings) {
  return {
    ImportDeclaration(path) {
      const source = path.node.source.value;
      for (const specifier of path.node.specifiers) {
        fileImports.set(specifier.local.name, source);
        const imported = importedName(specifier);
        componentImports.set(specifier.local.name, { source, importedName: imported, kind: "import" });

        if (source === "react") {
          if (imported === "default" || imported === "*") {
            rememberBinding(reactBindings.namespaces, specifier.local);
          } else if (REACT_CLASS_BASES.has(imported)) {
            rememberBinding(reactBindings.classBases, specifier.local);
          }
        }
      }
    },
    VariableDeclarator(path) {
      const init = path.node.init;
      if (
        init &&
        init.type === "CallExpression" &&
        init.callee.type === "Identifier" &&
        init.callee.name === "require" &&
        init.arguments.length > 0 &&
        init.arguments[0].type === "StringLiteral"
      ) {
        const source = init.arguments[0].value;
        const id = path.node.id;
        if (id.type === "Identifier") {
          fileImports.set(id.name, source);
          if (source === "react") rememberBinding(reactBindings.namespaces, id);
        } else if (id.type === "ObjectPattern") {
          for (const prop of id.properties) {
            if (prop.value && prop.value.type === "Identifier") {
              fileImports.set(prop.value.name, source);
              const imported = t.isIdentifier(prop.key) || t.isStringLiteral(prop.key)
                ? prop.key.name ?? prop.key.value
                : null;
              if (source === "react" && REACT_CLASS_BASES.has(imported)) {
                rememberBinding(reactBindings.classBases, prop.value);
              }
            }
          }
        }
      }
    }
  };
}

/**
 * Collects all Identifier names referenced inside a given AST node subtree,
 * only keeping those that match known file-level imports.
 */
function collectReferencedImports(bodyPath, fileImports, componentPath) {
  const referenced = new Set();
  bodyPath.traverse({
    Identifier(path) {
      if (!path.isReferencedIdentifier() || !fileImports.has(path.node.name)) return;
      const referencedBinding = path.scope.getBinding(path.node.name);
      const importedBinding = componentPath.scope.getBinding(path.node.name);
      if (referencedBinding && referencedBinding === importedBinding) referenced.add(path.node.name);
    },
  });
  return referenced;
}

/**
 * Extracts JSX element names rendered by a component (for component-renders-child relationships).
 * Only returns PascalCase names (other components), not lowercase (HTML elements).
 */
function collectRenderedComponents(bodyNode) {
  const rendered = new Set();

  function walk(node) {
    if (!node || typeof node !== "object") return;
    if (t.isJSXOpeningElement(node)) {
      const nameNode = node.name;
      if (t.isJSXIdentifier(nameNode) && /^[A-Z]/.test(nameNode.name)) {
        rendered.add(nameNode.name);
      }
      if (t.isJSXMemberExpression(nameNode) && t.isJSXIdentifier(nameNode.object)) {
        rendered.add(nameNode.object.name);
      }
    }
    for (const key of t.VISITOR_KEYS[node.type] || []) {
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(walk);
      } else if (t.isNode(child)) {
        walk(child);
      }
    }
  }

  walk(bodyNode);
  return rendered;
}

class ComponentWalker extends ASTWalker {
  createFileContext() {
    return {
      fileImports: new Map(),
      componentImports: new Map(),
      reactBindings: { namespaces: new Map(), classBases: new Map() },
    };
  }

  createPreVisitors(_file, fileContext) {
    return createImportVisitors(
      fileContext.fileImports,
      fileContext.componentImports,
      fileContext.reactBindings
    );
  }

  createVisitors(file, fileContext, _context, components) {
    const { fileImports, componentImports, reactBindings } = fileContext;
    return {
      FunctionDeclaration(path) {
        const name = path.node.id?.name;
        if (name && /^[A-Z]/.test(name) && isJSXReturningFunction(path.node)) { // default components : should match PascalCase and return JSX
          const body = path.node.body;
          const bodyPath = path.get("body");
          const usedImports = collectReferencedImports(bodyPath, fileImports, path);
          const renderedChildren = collectRenderedComponents(body);

          components.push({
            name,
            type: "FunctionComponent",
            filePath: file.filePath,
            loc: path.node.loc,
            bodyNode: body,
            componentPath: path,
            bodyPath,
            usedImports: Object.fromEntries(
              [...usedImports].map((id) => [id, fileImports.get(id)])
            ),
            renderedComponents: [...renderedChildren],
            componentImports: Object.fromEntries(componentImports),
            params: path.node.params
          });
        }
      },

      VariableDeclarator(path) { 
        const id = path.node.id;
        const init = path.node.init;

        if (
          id?.type === "Identifier" &&
          /^[A-Z]/.test(id.name) &&
          (init?.type === "ArrowFunctionExpression" || init?.type === "FunctionExpression") && //Arrow function components: same as function declaration but also check for arrow functions
          isJSXReturningFunction(init)
        ) { 
          const body = init.body;
          const componentPath = path.get("init");
          const bodyPath = componentPath.get("body");
          const usedImports = collectReferencedImports(bodyPath, fileImports, componentPath);
          const renderedChildren = collectRenderedComponents(body);

          components.push({
            name: id.name,
            type: "ArrowFunctionComponent",
            filePath: file.filePath,
            loc: path.node.loc,
            bodyNode: body,
            componentPath,
            bodyPath,
            usedImports: Object.fromEntries(
              [...usedImports].map((id) => [id, fileImports.get(id)])
            ),
            renderedComponents: [...renderedChildren],
            componentImports: Object.fromEntries(componentImports),
            params: init.params
          });
        }
      },

      ClassDeclaration(path) {
        const name = path.node.id?.name;

        if (
          name &&
          /^[A-Z]/.test(name) &&
          isReactClassComponent(path, reactBindings)
        ) {
          const body = path.node.body;
          const bodyPath = path.get("body");
          const usedImports = collectReferencedImports(bodyPath, fileImports, path);
          const renderedChildren = collectRenderedComponents(body);

          components.push({
            name,
            type: "ClassComponent",
            filePath: file.filePath,
            loc: path.node.loc,
            bodyNode: body,
            componentPath: path,
            bodyPath,
            usedImports: Object.fromEntries(
              [...usedImports].map((id) => [id, fileImports.get(id)])
            ),
            renderedComponents: [...renderedChildren], // to build the component graph, we need those to resolve these names to actual components in a later step
            componentImports: Object.fromEntries(componentImports),
            params: null // class components access props via this.props
          });
        }
      }
    };
  }
}

function extractComponents(parsedFiles) {
  return new ComponentWalker().walk(parsedFiles);
}

module.exports = extractComponents;
module.exports.ComponentWalker = ComponentWalker;
module.exports.isJSXReturningFunction = isJSXReturningFunction;
module.exports.collectReferencedImports = collectReferencedImports;
module.exports.collectRenderedComponents = collectRenderedComponents;
module.exports.isReactClassComponent = isReactClassComponent;
