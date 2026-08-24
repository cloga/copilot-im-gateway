import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createReleaseArchive } from "./package-release.mjs";
import { validateReleaseArchive } from "./validate-release.mjs";

const firstDirectory = await mkdtemp(
  path.join(os.tmpdir(), "copilot-im-gateway-release-a-"),
);
const secondDirectory = await mkdtemp(
  path.join(os.tmpdir(), "copilot-im-gateway-release-b-"),
);

try {
  const first = await createReleaseArchive({
    outputDirectory: firstDirectory,
  });
  const second = await createReleaseArchive({
    outputDirectory: secondDirectory,
  });
  await validateReleaseArchive(first.archivePath, first.checksumPath);
  await validateReleaseArchive(second.archivePath, second.checksumPath);

  if (first.digest !== second.digest) {
    throw new Error("Release packaging is not deterministic");
  }
  console.error(`Verified deterministic release SHA-256 ${first.digest}`);
} finally {
  await Promise.all([
    rm(firstDirectory, { force: true, recursive: true }),
    rm(secondDirectory, { force: true, recursive: true }),
  ]);
}
