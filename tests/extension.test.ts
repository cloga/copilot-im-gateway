import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

describe("Copilot extension security posture", () => {
  it("uses the official extension runtime and never approveAll", () => {
    const extension = readFileSync(
      path.join(
        process.cwd(),
        ".github",
        "extensions",
        "im-gateway",
        "extension.mjs",
      ),
      "utf8",
    );
    expect(extension).toContain("joinSession");
    expect(extension).toContain("onPermissionRequest");
    expect(extension).toContain('kind: "approve-once"');
    expect(extension).not.toContain("approveAll");
    expect(extension).not.toContain("assistant.reasoning");
  });
});
