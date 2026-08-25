import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

export const daemonRuntimeEntrypoint = "dist/daemon/main.js";
export const daemonRuntimeManifest = "daemon-runtime-closure.json";

/**
 * @param {string} modulePath
 */
function normalizeModulePath(modulePath) {
  const normalized = path.posix.normalize(modulePath.replaceAll("\\", "/"));
  if (
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    path.posix.isAbsolute(normalized)
  ) {
    throw new Error(`ESM closure path escapes its package root: ${modulePath}`);
  }
  return normalized.replace(/^\.\//u, "");
}

/**
 * @param {string} source
 * @param {string} modulePath
 */
export function findRelativeEsmSpecifiers(source, modulePath = "module.js") {
  const sourceFile = ts.createSourceFile(
    modulePath,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.JS,
  );
  /** @type {Set<string>} */
  const specifiers = new Set();
  /** @param {string} value */
  const addSpecifier = (value) => {
    if (/^\.\.?\//u.test(value)) {
      specifiers.add(value);
    }
  };
  /** @param {import("typescript").Node} node */
  const visit = (node) => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier !== undefined &&
      ts.isStringLiteralLike(node.moduleSpecifier)
    ) {
      addSpecifier(node.moduleSpecifier.text);
    } else if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments.length >= 1
    ) {
      const [argument] = node.arguments;
      if (argument !== undefined && ts.isStringLiteralLike(argument)) {
        addSpecifier(argument.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return [...specifiers].sort((left, right) =>
    left.localeCompare(right, "en"));
}

/**
 * @param {{
 *   entrypoint: string,
 *   readModule: (modulePath: string) => Promise<string>,
 * }} options
 */
export async function collectEsmClosure(options) {
  const entrypoint = normalizeModulePath(options.entrypoint);
  /** @type {Array<{ modulePath: string, importedBy: string | undefined }>} */
  const pending = [{ modulePath: entrypoint, importedBy: undefined }];
  const visited = new Set();
  while (pending.length > 0) {
    const next = pending.shift();
    if (next === undefined || visited.has(next.modulePath)) {
      continue;
    }
    let source;
    try {
      source = await options.readModule(next.modulePath);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const importer = next.importedBy === undefined
        ? ""
        : ` imported by ${next.importedBy}`;
      throw new Error(
        `ESM runtime dependency is missing: ${next.modulePath}${importer}. ${message}`,
        { cause: error },
      );
    }
    visited.add(next.modulePath);
    for (const specifier of findRelativeEsmSpecifiers(source, next.modulePath)) {
      const dependency = normalizeModulePath(
        path.posix.join(path.posix.dirname(next.modulePath), specifier),
      );
      if (!visited.has(dependency)) {
        pending.push({ modulePath: dependency, importedBy: next.modulePath });
      }
    }
  }
  return [...visited].sort((left, right) =>
    left.localeCompare(right, "en"));
}

/**
 * @param {string} root
 * @param {string} [entrypoint]
 */
export async function collectFilesystemEsmClosure(
  root,
  entrypoint = daemonRuntimeEntrypoint,
) {
  const resolvedRoot = path.resolve(root);
  return collectEsmClosure({
    entrypoint,
    readModule: async (modulePath) =>
      readFile(
        path.join(resolvedRoot, ...modulePath.split("/")),
        "utf8",
      ),
  });
}

/**
 * @param {string} root
 * @param {string} [entrypoint]
 */
export async function createEsmClosureManifest(
  root,
  entrypoint = daemonRuntimeEntrypoint,
) {
  return {
    version: 1,
    entrypoint: normalizeModulePath(entrypoint),
    files: await collectFilesystemEsmClosure(root, entrypoint),
  };
}

/**
 * @param {unknown} value
 */
export function parseEsmClosureManifest(value) {
  if (
    typeof value !== "object" ||
    value === null ||
    !("version" in value) ||
    value.version !== 1 ||
    !("entrypoint" in value) ||
    typeof value.entrypoint !== "string" ||
    !("files" in value) ||
    !Array.isArray(value.files) ||
    !value.files.every((entry) => typeof entry === "string")
  ) {
    throw new Error("Daemon runtime closure manifest is invalid.");
  }
  const entrypoint = normalizeModulePath(value.entrypoint);
  const files = value.files.map(normalizeModulePath);
  const sorted = [...new Set(files)].sort((left, right) =>
    left.localeCompare(right, "en"));
  if (
    files.length !== sorted.length ||
    files.some((entry, index) => entry !== sorted[index]) ||
    !files.includes(entrypoint)
  ) {
    throw new Error(
      "Daemon runtime closure manifest files must be unique, sorted, and include the entrypoint.",
    );
  }
  return { version: 1, entrypoint, files };
}

/**
 * @param {{
 *   manifest: unknown,
 *   readModule: (modulePath: string) => Promise<string>,
 * }} options
 */
export async function validateEsmClosureManifest(options) {
  const manifest = parseEsmClosureManifest(options.manifest);
  const actual = await collectEsmClosure({
    entrypoint: manifest.entrypoint,
    readModule: options.readModule,
  });
  if (
    actual.length !== manifest.files.length ||
    actual.some((entry, index) => entry !== manifest.files[index])
  ) {
    throw new Error(
      `Daemon runtime closure manifest does not match imports. Expected ${actual.join(", ")}.`,
    );
  }
  return manifest;
}

/**
 * @param {string} root
 * @param {string} outputPath
 * @param {string} [entrypoint]
 */
export async function writeEsmClosureManifest(
  root,
  outputPath,
  entrypoint = daemonRuntimeEntrypoint,
) {
  const manifest = await createEsmClosureManifest(root, entrypoint);
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return manifest;
}

async function runCli() {
  const [operation, rootArgument, targetArgument, entrypointArgument] =
    process.argv.slice(2);
  if (operation === "write" && rootArgument && targetArgument) {
    await writeEsmClosureManifest(
      path.resolve(rootArgument),
      path.resolve(targetArgument),
      entrypointArgument,
    );
    return;
  }
  if (operation === "verify" && rootArgument && targetArgument) {
    const root = path.resolve(rootArgument);
    const manifest = JSON.parse(
      await readFile(path.resolve(targetArgument), "utf8"),
    );
    await validateEsmClosureManifest({
      manifest,
      readModule: async (modulePath) =>
        readFile(path.join(root, ...modulePath.split("/")), "utf8"),
    });
    return;
  }
  if (operation === "check" && rootArgument && targetArgument) {
    await collectFilesystemEsmClosure(
      path.resolve(rootArgument),
      targetArgument,
    );
    return;
  }
  throw new Error(
    "Usage: esm-closure.mjs write <root> <manifest> [entrypoint] | verify <root> <manifest> | check <root> <entrypoint>",
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runCli();
}
