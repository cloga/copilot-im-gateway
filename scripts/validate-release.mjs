import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const requiredEntries = [
  "package/.env.example",
  "package/.github/extensions/im-gateway/canvas.mjs",
  "package/.github/extensions/im-gateway/extension.mjs",
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
  const archives = files.filter((file) => file.endsWith(".tgz"));
  if (archives.length !== 1) {
    throw new Error(
      `Expected exactly one release archive, found ${archives.length}`,
    );
  }
  const archive = archives[0];
  if (!archive) {
    throw new Error("Release archive was not found");
  }
  return path.join(releaseDirectory, archive);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const archivePath = process.argv[2]
    ? path.resolve(process.argv[2])
    : await findReleaseArchive();
  await validateReleaseArchive(archivePath, `${archivePath}.sha256`);
  console.error(`Validated ${archivePath}`);
}
