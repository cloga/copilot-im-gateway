import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  collectFilesystemEsmClosure,
  daemonRuntimeEntrypoint,
  daemonRuntimeManifest,
  writeEsmClosureManifest,
} from "./release/esm-closure.mjs";

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
  "scripts/release/stop-daemon.ps1",
];

const crc32Table = Array.from({ length: 256 }, (_, value) => {
  let current = value;
  for (let bit = 0; bit < 8; bit += 1) {
    current = (current & 1) === 1
      ? 0xedb88320 ^ (current >>> 1)
      : current >>> 1;
  }
  return current >>> 0;
});

/**
 * @param {string} root
 */
export async function assertBuildOutput(root) {
  try {
    const entrypoint = path.join(
      root,
      ...daemonRuntimeEntrypoint.split("/"),
    );
    if (!(await stat(entrypoint)).isFile()) {
      throw new Error("not a file");
    }
  } catch {
    throw new Error(
      "Release build output is missing: dist/daemon/main.js. Run npm run build first.",
    );
  }
  return collectFilesystemEsmClosure(root, daemonRuntimeEntrypoint);
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
  await rename(
    path.join(stage, "scripts", "release", "stop-daemon.ps1"),
    path.join(stage, "stop-daemon.ps1"),
  );
  await rm(path.join(stage, "scripts"), { recursive: true });
  await writeEsmClosureManifest(
    stage,
    path.join(stage, daemonRuntimeManifest),
  );
}

/**
 * @param {string} directory
 * @param {string} [prefix]
 * @returns {Promise<Array<{ name: string, contents: Buffer }>>}
 */
async function collectFiles(directory, prefix = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) =>
    left.name.localeCompare(right.name, "en"))) {
    const relativePath = prefix
      ? `${prefix}/${entry.name}`
      : entry.name;
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await collectFiles(absolutePath, relativePath));
    } else if (entry.isFile()) {
      files.push({
        name: `package/${relativePath.replaceAll("\\", "/")}`,
        contents: await readFile(absolutePath),
      });
    } else {
      throw new Error(`Unsupported release input: ${relativePath}`);
    }
  }
  return files;
}

/**
 * @param {Buffer} contents
 */
function crc32(contents) {
  let checksum = 0xffffffff;
  for (const byte of contents) {
    const tableValue = crc32Table[(checksum ^ byte) & 0xff];
    if (tableValue === undefined) {
      throw new Error("CRC-32 table lookup failed");
    }
    checksum = tableValue ^ (checksum >>> 8);
  }
  return (checksum ^ 0xffffffff) >>> 0;
}

/**
 * Create a ZIP with stored entries, fixed timestamps, and stable ordering.
 *
 * @param {string} stage
 * @param {string} archivePath
 */
export async function createDeterministicZip(stage, archivePath) {
  const files = await collectFiles(stage);
  const localRecords = [];
  const centralRecords = [];
  let offset = 0;

  for (const file of files) {
    const name = Buffer.from(file.name, "utf8");
    const checksum = crc32(file.contents);
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0x0800, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0x0021, 12);
    localHeader.writeUInt32LE(checksum, 14);
    localHeader.writeUInt32LE(file.contents.length, 18);
    localHeader.writeUInt32LE(file.contents.length, 22);
    localHeader.writeUInt16LE(name.length, 26);

    localRecords.push(localHeader, name, file.contents);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(0x0314, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0x0021, 14);
    centralHeader.writeUInt32LE(checksum, 16);
    centralHeader.writeUInt32LE(file.contents.length, 20);
    centralHeader.writeUInt32LE(file.contents.length, 24);
    centralHeader.writeUInt16LE(name.length, 28);
    centralHeader.writeUInt32LE(0o100644 * 0x10000, 38);
    centralHeader.writeUInt32LE(offset, 42);
    centralRecords.push(centralHeader, name);

    offset += localHeader.length + name.length + file.contents.length;
  }

  const centralDirectory = Buffer.concat(centralRecords);
  const endRecord = Buffer.alloc(22);
  endRecord.writeUInt32LE(0x06054b50, 0);
  endRecord.writeUInt16LE(files.length, 8);
  endRecord.writeUInt16LE(files.length, 10);
  endRecord.writeUInt32LE(centralDirectory.length, 12);
  endRecord.writeUInt32LE(offset, 16);

  await writeFile(
    archivePath,
    Buffer.concat([...localRecords, centralDirectory, endRecord]),
  );
}

/**
 * @param {string} archivePath
 */
export async function writeChecksum(archivePath) {
  const contents = await readFile(archivePath);
  const digest = createHash("sha256").update(contents).digest("hex");
  const checksumPath = `${archivePath}.sha256`;
  await writeFile(
    checksumPath,
    `${digest}  ${path.basename(archivePath)}\n`,
    "utf8",
  );
  return { archivePath, checksumPath, digest };
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
export async function createReleaseArtifacts(options = {}) {
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
    const tgzPath = path.join(
      outputDirectory,
      `copilot-im-gateway-v${manifest.version}.tgz`,
    );
    const windowsZipPath = path.join(
      outputDirectory,
      `copilot-im-gateway-v${manifest.version}-windows.zip`,
    );
    await Promise.all([
      rm(tgzPath, { force: true }),
      rm(windowsZipPath, { force: true }),
    ]);
    await rename(path.join(outputDirectory, packedFilename), tgzPath);
    await createDeterministicZip(stage, windowsZipPath);

    return {
      tgz: await writeChecksum(tgzPath),
      windowsZip: await writeChecksum(windowsZipPath),
    };
  } finally {
    await rm(stage, { force: true, recursive: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const artifacts = await createReleaseArtifacts();
  for (const artifact of Object.values(artifacts)) {
    console.error(`Created ${artifact.archivePath}`);
    console.error(`Created ${artifact.checksumPath}`);
  }
}
