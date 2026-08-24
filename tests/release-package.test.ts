import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { assertBuildOutput } from "../scripts/package-release.mjs";

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
});
