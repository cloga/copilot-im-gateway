import { readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

export const daemonRuntimeEntrypoint = "dist/daemon/main.js";
export const daemonRuntimeManifest = "daemon-runtime-closure.json";
export const esmClosureManifestVersion = 1;

const encodedPathControl = /%(?:00|2e|2f|5c)/iu;
const urlScheme = /^[a-z][a-z\d+.-]*:/iu;

/**
 * @param {string} root
 * @param {string} candidate
 */
function isPathInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return (
    relative === "" ||
    (
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative)
    )
  );
}

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
function findLiteralEsmSpecifiers(source, modulePath) {
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
    specifiers.add(value);
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
 * @param {string} source
 * @param {string} modulePath
 */
export function findRelativeEsmSpecifiers(source, modulePath = "module.js") {
  return findLiteralEsmSpecifiers(source, modulePath).filter((specifier) =>
    /^\.\.?\//u.test(specifier));
}

/**
 * @param {string} packageRoot
 * @param {string} importerPath
 * @param {string} specifier
 */
function resolvePackageImport(packageRoot, importerPath, specifier) {
  const hasControlCharacter = [...specifier].some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 0x1f || codePoint === 0x7f);
  });
  if (
    specifier.includes("\0") ||
    specifier.includes("\\") ||
    hasControlCharacter ||
    specifier.startsWith(" ") ||
    specifier.endsWith(" ") ||
    encodedPathControl.test(specifier)
  ) {
    throw new Error(
      `ESM import uses an unsafe encoded or decoded path: ${specifier} imported by ${importerPath}.`,
    );
  }
  if (
    specifier.includes("?") ||
    specifier.includes("#")
  ) {
    throw new Error(
      `ESM import query strings and fragments are unsupported: ${specifier} imported by ${importerPath}.`,
    );
  }

  const isRelative = /^\.\.?\//u.test(specifier);
  const hasScheme = urlScheme.test(specifier);
  if (/^node:/iu.test(specifier)) {
    return undefined;
  }
  if (
    !isRelative &&
    !hasScheme &&
    !specifier.startsWith("/") &&
    !specifier.startsWith("\\")
  ) {
    if (specifier === "." || specifier === ".." || specifier.startsWith(".")) {
      throw new Error(
        `ESM import is a malformed relative specifier: ${specifier} imported by ${importerPath}.`,
      );
    }
    return undefined;
  }

  const importerAbsolute = path.resolve(
    packageRoot,
    ...importerPath.split("/"),
  );
  let resolvedUrl;
  try {
    resolvedUrl = new URL(specifier, pathToFileURL(importerAbsolute));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `ESM import URL is invalid: ${specifier} imported by ${importerPath}. ${message}`,
      { cause: error },
    );
  }
  if (resolvedUrl.protocol !== "file:") {
    throw new Error(
      `ESM import must resolve to a file URL: ${specifier} imported by ${importerPath}.`,
    );
  }
  if (resolvedUrl.search !== "" || resolvedUrl.hash !== "") {
    throw new Error(
      `ESM import query strings and fragments are unsupported: ${specifier} imported by ${importerPath}.`,
    );
  }

  let resolvedPath;
  try {
    resolvedPath = fileURLToPath(resolvedUrl);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `ESM import file URL is invalid: ${specifier} imported by ${importerPath}. ${message}`,
      { cause: error },
    );
  }
  if (resolvedPath.includes("\0")) {
    throw new Error(
      `ESM import decodes to an unsafe path: ${specifier} imported by ${importerPath}.`,
    );
  }

  const canonicalPath = path.resolve(resolvedPath);
  if (!isPathInside(packageRoot, canonicalPath)) {
    throw new Error(
      `ESM closure path escapes its package root: ${specifier} imported by ${importerPath}.`,
    );
  }
  const packagePath = path.relative(packageRoot, canonicalPath)
    .split(path.sep)
    .join("/");
  return normalizeModulePath(packagePath);
}

/**
 * @param {{
 *   packageRoot?: string,
 *   entrypoint: string,
 *   readModule: (modulePath: string) => Promise<string>,
 * }} options
 */
export async function collectEsmClosure(options) {
  const packageRoot = path.resolve(options.packageRoot ?? ".");
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
    for (const specifier of findLiteralEsmSpecifiers(source, next.modulePath)) {
      const dependency = resolvePackageImport(
        packageRoot,
        next.modulePath,
        specifier,
      );
      if (dependency !== undefined && !visited.has(dependency)) {
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
  let canonicalRoot;
  try {
    canonicalRoot = await realpath(resolvedRoot);
  } catch {
    canonicalRoot = resolvedRoot;
  }
  return collectEsmClosure({
    packageRoot: canonicalRoot,
    entrypoint,
    readModule: async (modulePath) => {
      const lexicalPath = path.resolve(
        canonicalRoot,
        ...modulePath.split("/"),
      );
      const canonicalPath = await realpath(lexicalPath);
      if (!isPathInside(canonicalRoot, canonicalPath)) {
        throw new Error(
          `ESM runtime dependency resolves outside its package root: ${modulePath}.`,
        );
      }
      return readFile(canonicalPath, "utf8");
    },
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
  const normalizedEntrypoint = normalizeModulePath(entrypoint);
  if (normalizedEntrypoint !== daemonRuntimeEntrypoint) {
    throw new Error(
      `Daemon runtime closure entrypoint must be ${daemonRuntimeEntrypoint}.`,
    );
  }
  return {
    version: esmClosureManifestVersion,
    entrypoint: daemonRuntimeEntrypoint,
    files: await collectFilesystemEsmClosure(root, daemonRuntimeEntrypoint),
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
    !("entrypoint" in value) ||
    typeof value.entrypoint !== "string" ||
    !("files" in value) ||
    !Array.isArray(value.files) ||
    !value.files.every((entry) => typeof entry === "string")
  ) {
    throw new Error("Daemon runtime closure manifest is invalid.");
  }
  if (value.version !== esmClosureManifestVersion) {
    throw new Error(
      `Daemon runtime closure manifest version must be ${esmClosureManifestVersion}.`,
    );
  }
  if (
    value.entrypoint !== daemonRuntimeEntrypoint
  ) {
    throw new Error(
      `Daemon runtime closure manifest entrypoint must be ${daemonRuntimeEntrypoint}.`,
    );
  }

  const files = value.files.map((entry) => {
    const canonical = normalizeModulePath(entry);
    if (entry !== canonical) {
      throw new Error(
        `Daemon runtime closure manifest contains a non-canonical path: ${entry}.`,
      );
    }
    return canonical;
  });
  const sorted = [...new Set(files)].sort((left, right) =>
    left.localeCompare(right, "en"));
  if (
    files.length !== sorted.length ||
    files.some((entry, index) => entry !== sorted[index]) ||
    !files.includes(daemonRuntimeEntrypoint)
  ) {
    throw new Error(
      "Daemon runtime closure manifest files must be unique, sorted, and include the entrypoint.",
    );
  }
  return {
    version: esmClosureManifestVersion,
    entrypoint: daemonRuntimeEntrypoint,
    files,
  };
}

/**
 * @param {{
 *   manifest: unknown,
 *   expectedEntrypoint?: string,
 *   packageRoot?: string,
 *   readModule: (modulePath: string) => Promise<string>,
 * }} options
 */
export async function validateEsmClosureManifest(options) {
  const expectedEntrypoint =
    options.expectedEntrypoint ?? daemonRuntimeEntrypoint;
  if (expectedEntrypoint !== daemonRuntimeEntrypoint) {
    throw new Error(
      `Expected daemon runtime entrypoint must be ${daemonRuntimeEntrypoint}.`,
    );
  }
  const manifest = parseEsmClosureManifest(options.manifest);
  const actual = await collectEsmClosure({
    entrypoint: expectedEntrypoint,
    readModule: options.readModule,
    ...(options.packageRoot === undefined
      ? {}
      : { packageRoot: options.packageRoot }),
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
  const [operation, rootArgument, targetArgument, extraArgument] =
    process.argv.slice(2);
  if (
    operation === "write" &&
    rootArgument &&
    targetArgument &&
    extraArgument === undefined
  ) {
    await writeEsmClosureManifest(
      path.resolve(rootArgument),
      path.resolve(targetArgument),
    );
    return;
  }
  if (
    operation === "verify" &&
    rootArgument &&
    targetArgument &&
    extraArgument === undefined
  ) {
    const root = path.resolve(rootArgument);
    const manifest = JSON.parse(
      await readFile(path.resolve(targetArgument), "utf8"),
    );
    await validateEsmClosureManifest({
      manifest,
      expectedEntrypoint: daemonRuntimeEntrypoint,
      packageRoot: root,
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
    "Usage: esm-closure.mjs write <root> <manifest> | verify <root> <manifest> | check <root> <entrypoint>",
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runCli();
}
