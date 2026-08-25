import { describe, expect, it } from "vitest";
import {
  chunkOutboundText,
  constantTimeTokenEqual,
  isPathInside,
  redactText,
} from "../src/core/security.js";
import { toRouteKey } from "../src/core/contracts.js";

describe("security primitives", () => {
  it("compares bearer tokens without length timing differences", () => {
    expect(constantTimeTokenEqual("correct-token", "correct-token")).toBe(true);
    expect(constantTimeTokenEqual("wrong", "correct-token")).toBe(false);
    expect(constantTimeTokenEqual(undefined, "correct-token")).toBe(false);
  });

  it("redacts secrets and local absolute paths", () => {
    const text =
      "Authorization: Bearer secret.value\n" +
      "api_key=super-secret\n" +
      "C:\\Users\\alice\\private\\file.txt\n" +
      "/home/alice/private/file.txt";
    const redacted = redactText(text);
    expect(redacted).not.toContain("secret.value");
    expect(redacted).not.toContain("super-secret");
    expect(redacted).not.toContain("alice");
    expect(redacted).toContain("<redacted:path>");
  });

  it("bounds and chunks outbound messages", () => {
    const chunks = chunkOutboundText("word ".repeat(200), 50, 3);
    expect(chunks).toHaveLength(3);
    expect(chunks.every((chunk) => chunk.length <= 50)).toBe(true);
    expect(chunks.at(-1)).toContain("[output truncated]");
  });

  it("hashes length-prefixed full route identities without delimiter collisions", () => {
    const route = {
      tenantId: "local" as const,
      channelId: "a:b",
      accountId: "bot",
      conversationId: "c",
      senderId: "owner",
    };
    expect(toRouteKey(route)).toHaveLength(64);
    expect(toRouteKey(route)).not.toBe(
      toRouteKey({ ...route, channelId: "a", conversationId: "b:c" }),
    );
    expect(toRouteKey(route)).not.toBe(
      toRouteKey({ ...route, accountId: "other" }),
    );
  });

  it("recognizes only paths inside the allowed root", () => {
    expect(isPathInside("/repo", "/repo/src/index.ts")).toBe(true);
    expect(isPathInside("/repo", "/other/secret.txt")).toBe(false);
  });
});
