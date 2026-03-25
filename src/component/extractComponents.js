const traverse = require("@babel/traverse").default;
const t = require("@babel/types");

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

/**
 * Collects the set of file-level imported identifiers that exist in this file AST.
 * Returns a Map: identifierName -> packageSource
 */
function collectFileImports(ast) {
  const imports = new Map();

  traverse(ast, {
    ImportDeclaration(path) {
      const source = path.node.source.value;
      for (const spec of path.node.specifiers) {
        imports.set(spec.local.name, source);
      }
    },
    // Also handle const x = require("pkg")
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
          imports.set(id.name, source);
        } else if (id.type === "ObjectPattern") {
          for (const prop of id.properties) {
            if (prop.value && prop.value.type === "Identifier") {
              imports.set(prop.value.name, source);
            }
          }
        }
      }
    }
  });

  return imports;
}

/**
 * Collects all Identifier names referenced inside a given AST node subtree,
 * only keeping those that match known file-level imports.
 */
function collectReferencedImports(bodyNode, fileImports) {
  const referenced = new Set();

  function walk(node) {
    if (!node || typeof node !== "object") return;
    if (t.isIdentifier(node) && fileImports.has(node.name)) {
      referenced.add(node.name);
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

function extractComponents(parsedFiles) {
  const components = [];

  for (const file of parsedFiles) {
    const fileImports = collectFileImports(file.ast);

    traverse(file.ast, {
      FunctionDeclaration(path) {
        const name = path.node.id?.name;
        if (name && /^[A-Z]/.test(name) && isJSXReturningFunction(path.node)) {
          const body = path.node.body;
          const usedImports = collectReferencedImports(body, fileImports);
          const renderedChildren = collectRenderedComponents(body);

          components.push({
            name,
            type: "FunctionComponent",
            filePath: file.filePath,
            loc: path.node.loc,
            bodyNode: body,
            usedImports: Object.fromEntries(
              [...usedImports].map((id) => [id, fileImports.get(id)])
            ),
            renderedComponents: [...renderedChildren]
          });
        }
      },

      VariableDeclarator(path) {
        const id = path.node.id;
        const init = path.node.init;

        if (
          id?.type === "Identifier" &&
          /^[A-Z]/.test(id.name) &&
          (init?.type === "ArrowFunctionExpression" || init?.type === "FunctionExpression") &&
          isJSXReturningFunction(init)
        ) {
          const body = init.body;
          const usedImports = collectReferencedImports(body, fileImports);
          const renderedChildren = collectRenderedComponents(body);

          components.push({
            name: id.name,
            type: "ArrowFunctionComponent",
            filePath: file.filePath,
            loc: path.node.loc,
            bodyNode: body,
            usedImports: Object.fromEntries(
              [...usedImports].map((id) => [id, fileImports.get(id)])
            ),
            renderedComponents: [...renderedChildren]
          });
        }
      },

      ClassDeclaration(path) {
        const name = path.node.id?.name;
        const superClass = path.node.superClass;

        if (
          name &&
          /^[A-Z]/.test(name) &&
          superClass &&
          (
            superClass.type === "MemberExpression" ||
            superClass.type === "Identifier"
          )
        ) {
          const body = path.node.body;
          const usedImports = collectReferencedImports(body, fileImports);
          const renderedChildren = collectRenderedComponents(body);

          components.push({
            name,
            type: "ClassComponent",
            filePath: file.filePath,
            loc: path.node.loc,
            bodyNode: body,
            usedImports: Object.fromEntries(
              [...usedImports].map((id) => [id, fileImports.get(id)])
            ),
            renderedComponents: [...renderedChildren]
          });
        }
      }
    });
  }

  return components;
}

module.exports = extractComponents;