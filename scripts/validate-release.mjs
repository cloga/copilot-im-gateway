import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync, inflateRawSync } from "node:zlib";
import {
  daemonRuntimeEntrypoint,
  daemonRuntimeManifest,
  validateEsmClosureManifest,
} from "./release/esm-closure.mjs";

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
  "package/credential-key.ps1",
  `package/${daemonRuntimeManifest}`,
  "package/dist/daemon/main.js",
  "package/docs/manual-smoke-test.md",
  "package/install.ps1",
  "package/npm-shrinkwrap.json",
  "package/package.json",
  "package/start.ps1",
  "package/stop-daemon.ps1",
];

/**
 * @param {Buffer} value
 */
function readArchiveString(value) {
  const end = value.indexOf(0);
  return value.subarray(0, end < 0 ? value.length : end).toString("utf8");
}

/**
 * @param {string} archivePath
 */
function readTarArchive(archivePath) {
  const archive = gunzipSync(readFileSync(archivePath));
  const entries = new Map();
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      break;
    }
    const name = readArchiveString(header.subarray(0, 100));
    const prefix = readArchiveString(header.subarray(345, 500));
    const sizeText = readArchiveString(header.subarray(124, 136)).trim();
    const size = Number.parseInt(sizeText || "0", 8);
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new Error(`Invalid TAR entry size for ${name}`);
    }
    const type = header.subarray(156, 157).toString("utf8");
    const entryName = `${prefix ? `${prefix}/` : ""}${name}`
      .replace(/^\.\//u, "")
      .replaceAll("\\", "/")
      .replace(/\/$/u, "");
    const contentStart = offset + 512;
    const contentEnd = contentStart + size;
    if (contentEnd > archive.length) {
      throw new Error(`Truncated TAR entry: ${entryName}`);
    }
    if ((type === "" || type === "\0" || type === "0") && entryName) {
      entries.set(entryName, archive.subarray(contentStart, contentEnd));
    }
    offset = contentStart + Math.ceil(size / 512) * 512;
  }
  return entries;
}

/**
 * @param {string} archivePath
 */
function readZipArchive(archivePath) {
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
  const entries = new Map();
  for (let index = 0; index < entryCount; index += 1) {
    if (archive.readUInt32LE(offset) !== 0x02014b50) {
      throw new Error("Invalid ZIP central directory entry");
    }
    const nameLength = archive.readUInt16LE(offset + 28);
    const extraLength = archive.readUInt16LE(offset + 30);
    const commentLength = archive.readUInt16LE(offset + 32);
    const compression = archive.readUInt16LE(offset + 10);
    const compressedSize = archive.readUInt32LE(offset + 20);
    const uncompressedSize = archive.readUInt32LE(offset + 24);
    const localOffset = archive.readUInt32LE(offset + 42);
    const name = archive
      .subarray(offset + 46, offset + 46 + nameLength)
      .toString("utf8")
      .replaceAll("\\", "/")
      .replace(/\/$/u, "");
    if (name) {
      if (archive.readUInt32LE(localOffset) !== 0x04034b50) {
        throw new Error(`Invalid ZIP local entry: ${name}`);
      }
      const localNameLength = archive.readUInt16LE(localOffset + 26);
      const localExtraLength = archive.readUInt16LE(localOffset + 28);
      const contentStart =
        localOffset + 30 + localNameLength + localExtraLength;
      const compressed = archive.subarray(
        contentStart,
        contentStart + compressedSize,
      );
      const contents = compression === 0
        ? compressed
        : compression === 8
          ? inflateRawSync(compressed)
          : undefined;
      if (contents === undefined) {
        throw new Error(
          `Unsupported ZIP compression method ${compression}: ${name}`,
        );
      }
      if (contents.length !== uncompressedSize) {
        throw new Error(`Invalid ZIP entry size: ${name}`);
      }
      entries.set(name, contents);
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/**
 * @param {string} archivePath
 */
function readArchive(archivePath) {
  return archivePath.endsWith(".zip")
    ? readZipArchive(archivePath)
    : readTarArchive(archivePath);
}

/**
 * @param {string} archivePath
 * @param {string} checksumPath
 */
export async function validateReleaseArchive(archivePath, checksumPath) {
  const archiveEntries = readArchive(archivePath);
  const entries = new Set(archiveEntries.keys());
  const forbiddenState = [...entries].filter((entry) =>
    /(?:^|\/)(?:auth-token|credential-master-key(?:\..*)?|gateway\.sqlite(?:-.*)?)$/u
      .test(entry));
  if (forbiddenState.length > 0) {
    throw new Error(
      `Release archive contains generated credential state: ${forbiddenState.join(", ")}`,
    );
  }
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

  const manifestPath = `package/${daemonRuntimeManifest}`;
  const manifestContents = archiveEntries.get(manifestPath);
  if (manifestContents === undefined) {
    throw new Error(`Release archive is missing: ${manifestPath}`);
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestContents.toString("utf8"));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Daemon runtime closure manifest is not JSON: ${message}`);
  }
  await validateEsmClosureManifest({
    manifest,
    expectedEntrypoint: daemonRuntimeEntrypoint,
    packageRoot: path.resolve(path.dirname(archivePath), "package"),
    readModule: async (modulePath) => {
      const entryPath = `package/${modulePath}`;
      const contents = archiveEntries.get(entryPath);
      if (contents === undefined) {
        throw new Error(`Release archive entry is absent: ${entryPath}`);
      }
      return contents.toString("utf8");
    },
  });

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
