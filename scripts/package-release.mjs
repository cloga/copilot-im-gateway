import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const releaseInputs = [
  "dist",
  ".github/extensions/im-gateway",
  "docs",
  ".env.example",
  "README.md",
  "THIRD_PARTY_NOTICES.md",
  "package.json",
  "scripts/release/install.ps1",
  "scripts/release/start.ps1",
];

/**
 * @param {string} root
 */
export async function assertBuildOutput(root) {
  const entrypoint = path.join(root, "dist", "daemon", "main.js");
  try {
    if (!(await stat(entrypoint)).isFile()) {
      throw new Error("not a file");
    }
  } catch {
    throw new Error(
      "Release build output is missing: dist/daemon/main.js. Run npm run build first.",
    );
  }
}

/**
 * @param {string} source
 * @param {string} destination
 */
async function copyInput(source, destination) {
  try {
    await cp(source, destination, {
      force: true,
      recursive: true,
      preserveTimestamps: false,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Unable to copy release input ${source}: ${message}`);
  }
}

/**
 * @param {string} root
 * @param {string} stage
 */
async function prepareStage(root, stage) {
  await assertBuildOutput(root);

  for (const relativePath of releaseInputs) {
    await copyInput(
      path.join(root, relativePath),
      path.join(stage, relativePath),
    );
  }

  await copyInput(
    path.join(root, "package-lock.json"),
    path.join(stage, "npm-shrinkwrap.json"),
  );
  await rename(
    path.join(stage, "scripts", "release", "install.ps1"),
    path.join(stage, "install.ps1"),
  );
  await rename(
    path.join(stage, "scripts", "release", "start.ps1"),
    path.join(stage, "start.ps1"),
  );
  await rm(path.join(stage, "scripts"), { recursive: true });
}

/**
 * @param {string} stage
 * @param {string} outputDirectory
 */
function npmPack(stage, outputDirectory) {
  const npmCli = process.env.npm_execpath;
  if (!npmCli) {
    throw new Error("npm executable path is unavailable; run via npm run.");
  }

  const result = spawnSync(
    process.execPath,
    [
      npmCli,
      "pack",
      stage,
      "--pack-destination",
      outputDirectory,
      "--ignore-scripts",
      "--json",
    ],
    { encoding: "utf8" },
  );
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "npm pack failed");
  }

  /** @type {unknown} */
  const output = JSON.parse(result.stdout);
  if (
    !Array.isArray(output) ||
    output.length !== 1 ||
    typeof output[0] !== "object" ||
    output[0] === null ||
    !("filename" in output[0]) ||
    typeof output[0].filename !== "string"
  ) {
    throw new Error("npm pack returned an unexpected result");
  }
  return output[0].filename;
}

/**
 * @param {{ root?: string, outputDirectory?: string }} [options]
 */
export async function createReleaseArchive(options = {}) {
  const root = path.resolve(options.root ?? repositoryRoot);
  const outputDirectory = path.resolve(
    options.outputDirectory ?? path.join(root, "release"),
  );
  await mkdir(outputDirectory, { recursive: true });
  const stage = await mkdtemp(path.join(outputDirectory, ".stage-"));

  try {
    await prepareStage(root, stage);
    const manifest = JSON.parse(
      await readFile(path.join(stage, "package.json"), "utf8"),
    );
    if (typeof manifest.version !== "string") {
      throw new Error("package.json version is missing");
    }

    const packedFilename = npmPack(stage, outputDirectory);
    const archiveName = `copilot-im-gateway-v${manifest.version}.tgz`;
    const archivePath = path.join(outputDirectory, archiveName);
    await rm(archivePath, { force: true });
    await rename(path.join(outputDirectory, packedFilename), archivePath);

    const contents = await readFile(archivePath);
    const digest = createHash("sha256").update(contents).digest("hex");
    const checksumPath = `${archivePath}.sha256`;
    await writeFile(checksumPath, `${digest}  ${archiveName}\n`, "utf8");

    return { archivePath, checksumPath, digest };
  } finally {
    await rm(stage, { force: true, recursive: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { archivePath, checksumPath } = await createReleaseArchive();
  console.error(`Created ${archivePath}`);
  console.error(`Created ${checksumPath}`);
}
