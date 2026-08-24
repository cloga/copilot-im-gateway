import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createReleaseArtifacts } from "./package-release.mjs";
import { validateReleaseArchive } from "./validate-release.mjs";

const firstDirectory = await mkdtemp(
  path.join(os.tmpdir(), "copilot-im-gateway-release-a-"),
);
const secondDirectory = await mkdtemp(
  path.join(os.tmpdir(), "copilot-im-gateway-release-b-"),
);

try {
  const first = await createReleaseArtifacts({
    outputDirectory: firstDirectory,
  });
  const second = await createReleaseArtifacts({
    outputDirectory: secondDirectory,
  });
  for (const artifactName of /** @type {const} */ (["tgz", "windowsZip"])) {
    const firstArtifact = first[artifactName];
    const secondArtifact = second[artifactName];
    await validateReleaseArchive(
      firstArtifact.archivePath,
      firstArtifact.checksumPath,
    );
    await validateReleaseArchive(
      secondArtifact.archivePath,
      secondArtifact.checksumPath,
    );
    if (firstArtifact.digest !== secondArtifact.digest) {
      throw new Error(`${artifactName} release packaging is not deterministic`);
    }
    console.error(
      `Verified deterministic ${artifactName} SHA-256 ${firstArtifact.digest}`,
    );
  }
} finally {
  await Promise.all([
    rm(firstDirectory, { force: true, recursive: true }),
    rm(secondDirectory, { force: true, recursive: true }),
  ]);
}
