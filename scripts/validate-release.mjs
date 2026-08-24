import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

export const requiredEntries = [
  "package/.env.example",
  "package/.github/extensions/im-gateway/canvas.mjs",
  "package/.github/extensions/im-gateway/extension.mjs",
  "package/.github/extensions/im-gateway/extension-runtime.mjs",
  "package/.github/extensions/im-gateway/gateway-client.mjs",
  "package/README.md",
  "package/THIRD_PARTY_NOTICES.md",
  "package/dist/daemon/main.js",
  "package/docs/manual-smoke-test.md",
  "package/install.ps1",
  "package/npm-shrinkwrap.json",
  "package/package.json",
  "package/start.ps1",
];

/**
 * @param {string} archivePath
 */
function listArchive(archivePath) {
  if (archivePath.endsWith(".zip")) {
    return listZipArchive(archivePath);
  }
  const result = spawnSync("tar", ["-tzf", archivePath], {
    encoding: "utf8",
  });
  if (result.error) {
    throw new Error(`Unable to run tar: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Unable to list release archive");
  }
  return new Set(
    result.stdout
      .split(/\r?\n/u)
      .map((entry) => entry.replaceAll("\\", "/").replace(/\/$/u, ""))
      .filter(Boolean),
  );
}

/**
 * @param {string} archivePath
 */
function listZipArchive(archivePath) {
  const archive = readFileSync(archivePath);
  const endSignature = 0x06054b50;
  let endOffset = -1;
  for (
    let offset = archive.length - 22;
    offset >= Math.max(0, archive.length - 65_557);
    offset -= 1
  ) {
    if (archive.readUInt32LE(offset) === endSignature) {
      endOffset = offset;
      break;
    }
  }
  if (endOffset < 0) {
    throw new Error("Unable to find ZIP central directory");
  }

  const entryCount = archive.readUInt16LE(endOffset + 10);
  let offset = archive.readUInt32LE(endOffset + 16);
  const entries = new Set();
  for (let index = 0; index < entryCount; index += 1) {
    if (archive.readUInt32LE(offset) !== 0x02014b50) {
      throw new Error("Invalid ZIP central directory entry");
    }
    const nameLength = archive.readUInt16LE(offset + 28);
    const extraLength = archive.readUInt16LE(offset + 30);
    const commentLength = archive.readUInt16LE(offset + 32);
    const name = archive
      .subarray(offset + 46, offset + 46 + nameLength)
      .toString("utf8")
      .replaceAll("\\", "/")
      .replace(/\/$/u, "");
    if (name) {
      entries.add(name);
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/**
 * @param {string} archivePath
 * @param {string} checksumPath
 */
export async function validateReleaseArchive(archivePath, checksumPath) {
  const entries = listArchive(archivePath);
  const missing = requiredEntries.filter((entry) => !entries.has(entry));
  if (missing.length > 0) {
    throw new Error(`Release archive is missing: ${missing.join(", ")}`);
  }

  const forbidden = [...entries].filter(
    (entry) =>
      entry.startsWith("package/src/") ||
      entry.startsWith("package/tests/") ||
      entry.startsWith("package/node_modules/") ||
      (entry.startsWith("package/.env.") &&
        entry !== "package/.env.example"),
  );
  if (forbidden.length > 0) {
    throw new Error(`Release archive contains forbidden files: ${forbidden.join(", ")}`);
  }

  const archive = await readFile(archivePath);
  const actualDigest = createHash("sha256").update(archive).digest("hex");
  const checksum = (await readFile(checksumPath, "utf8")).trim();
  const [expectedDigest, expectedFilename] = checksum.split(/\s+/u);
  if (
    expectedDigest !== actualDigest ||
    expectedFilename !== path.basename(archivePath)
  ) {
    throw new Error("Release checksum does not match the archive");
  }
}

async function findReleaseArchive() {
  const releaseDirectory = path.join(repositoryRoot, "release");
  const files = await readdir(releaseDirectory);
  const archives = files.filter(
    (file) => file.endsWith(".tgz") || file.endsWith(".zip"),
  );
  if (archives.length !== 2) {
    throw new Error(
      `Expected exactly two release archives, found ${archives.length}`,
    );
  }
  return archives.map((archive) => path.join(releaseDirectory, archive));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const archivePaths = process.argv[2]
    ? [path.resolve(process.argv[2])]
    : await findReleaseArchive();
  for (const archivePath of archivePaths) {
    await validateReleaseArchive(archivePath, `${archivePath}.sha256`);
    console.error(`Validated ${archivePath}`);
  }
}
