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
  it("keeps the v2 daemon and extension in one release compatibility unit", async () => {
    expect(requiredEntries).toEqual(
      expect.arrayContaining([
        "package/dist/daemon/main.js",
        "package/.github/extensions/im-gateway/gateway-client.mjs",
        "package/.github/extensions/im-gateway/extension-runtime.mjs",
      ]),
    );
    const root = path.resolve(import.meta.dirname, "..");
    const daemon = await readFile(
      path.join(root, "src", "daemon", "http-server.ts"),
      "utf8",
    );
    const client = await readFile(
      path.join(
        root,
        ".github",
        "extensions",
        "im-gateway",
        "gateway-client.mjs",
      ),
      "utf8",
    );
    for (const capability of [
      "account-scoped-routing",
      "sender-bound-routing",
      "operation-bound-approvals",
      "reservation-ownership",
    ]) {
      expect(daemon).toContain(capability);
      expect(client).toContain(capability);
    }
    expect(daemon).toContain("gatewayApiVersion = 2");
    expect(client).toContain("supportedGatewayApiVersion = 2");
  });

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
    const incompleteStage = path.join(root, "incomplete");
    const firstArchive = path.join(root, "first.zip");
    const secondArchive = path.join(root, "second.zip");
    const incompleteArchive = path.join(root, "incomplete.zip");
    try {
      for (const entry of requiredEntries) {
        const relativePath = entry.replace(/^package\//u, "");
        for (const stage of [firstStage, secondStage]) {
          const destination = path.join(stage, ...relativePath.split("/"));
          await mkdir(path.dirname(destination), { recursive: true });
          await writeFile(destination, `fixture:${relativePath}\n`, "utf8");
        }
        if (
          entry !==
          "package/.github/extensions/im-gateway/extension-runtime.mjs"
        ) {
          const destination = path.join(
            incompleteStage,
            ...relativePath.split("/"),
          );
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

      await createDeterministicZip(incompleteStage, incompleteArchive);
      const incompleteChecksum = await writeChecksum(incompleteArchive);
      await expect(
        validateReleaseArchive(
          incompleteArchive,
          incompleteChecksum.checksumPath,
        ),
      ).rejects.toThrow("extension-runtime.mjs");

      await writeFile(firstChecksum.checksumPath, "invalid  first.zip\n", "utf8");
      await expect(
        validateReleaseArchive(firstArchive, firstChecksum.checksumPath),
      ).rejects.toThrow("checksum");
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("pins and wires the self-contained Windows installer", async () => {
    const root = path.resolve(import.meta.dirname, "..");
    const buildScript = await readFile(
      path.join(root, "scripts", "installer", "build-windows-installer.ps1"),
      "utf8",
    );
    const installer = await readFile(
      path.join(root, "scripts", "installer", "windows-installer.iss"),
      "utf8",
    );
    const releaseWorkflow = await readFile(
      path.join(root, ".github", "workflows", "release.yml"),
      "utf8",
    );
    const installScript = await readFile(
      path.join(root, "scripts", "release", "install.ps1"),
      "utf8",
    );

    expect(buildScript).toContain('$nodeVersion = "24.11.1"');
    expect(buildScript).toContain(
      '$nodeArchiveSha256 = "5355ae6d7c49eddcfde7d34ac3486820600a831bf81dc3bdca5c8db6a9bb0e76"',
    );
    expect(buildScript).toContain("npm-cli.js");
    expect(installer).toContain("PrivilegesRequired=lowest");
    expect(installer).toContain("ArchitecturesAllowed=x64compatible");
    expect(installer).toContain("Copilot-IM-Gateway-Setup-v{#AppVersion}-x64");
    expect(installer).not.toContain("runascurrentuser");
    expect(releaseWorkflow).toContain("npm run release:installer:smoke");
    expect(releaseWorkflow).toContain("release/*.exe");
    expect(installScript).toContain(
      "$nodeVersion.Major -eq 22 -and $nodeVersion.Minor -ge 13",
    );
    expect(installScript).toContain(
      "Node.js 22.13+ (excluding 23.x) or 24+ is required",
    );
    expect(installScript).not.toContain("22.12");
  });
});
