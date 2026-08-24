import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  assertBuildOutput,
  createDeterministicZip,
  writeChecksum,
} from "../scripts/package-release.mjs";
import {
  requiredEntries,
  validateReleaseArchive,
} from "../scripts/validate-release.mjs";

describe("release packaging", () => {
  it("rejects a repository without compiled daemon output", async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "copilot-im-gateway-missing-build-"),
    );
    try {
      await expect(assertBuildOutput(root)).rejects.toThrow(
        "dist/daemon/main.js",
      );
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("creates a deterministic Windows archive with validated contents", async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "copilot-im-gateway-windows-release-"),
    );
    const firstStage = path.join(root, "first");
    const secondStage = path.join(root, "second");
    const firstArchive = path.join(root, "first.zip");
    const secondArchive = path.join(root, "second.zip");
    try {
      for (const entry of requiredEntries) {
        const relativePath = entry.replace(/^package\//u, "");
        for (const stage of [firstStage, secondStage]) {
          const destination = path.join(stage, ...relativePath.split("/"));
          await mkdir(path.dirname(destination), { recursive: true });
          await writeFile(destination, `fixture:${relativePath}\n`, "utf8");
        }
      }

      await createDeterministicZip(firstStage, firstArchive);
      await createDeterministicZip(secondStage, secondArchive);
      const firstChecksum = await writeChecksum(firstArchive);
      const secondChecksum = await writeChecksum(secondArchive);

      await validateReleaseArchive(firstArchive, firstChecksum.checksumPath);
      await validateReleaseArchive(secondArchive, secondChecksum.checksumPath);
      expect(firstChecksum.digest).toBe(secondChecksum.digest);
      expect(
        createHash("sha256")
          .update(await readFile(firstArchive))
          .digest("hex"),
      ).toBe(firstChecksum.digest);

      await writeFile(firstChecksum.checksumPath, "invalid  first.zip\n", "utf8");
      await expect(
        validateReleaseArchive(firstArchive, firstChecksum.checksumPath),
      ).rejects.toThrow("checksum");
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });
});
