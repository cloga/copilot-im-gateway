import { describe, expect, it } from "vitest";
import {
  chunkOutboundText,
  constantTimeTokenEqual,
  isPathInside,
  redactText,
} from "../src/core/security.js";
import { isWellFormedUnicode, toRouteKey } from "../src/core/contracts.js";
import {
  v2AllowedSenderSchema,
  v2ApprovalRequestSchema,
} from "../src/daemon/schemas.js";

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

  it("rejects ill-formed Unicode before route hashing without conflating U+FFFD", () => {
    const route = {
      tenantId: "local" as const,
      channelId: "weixin-main",
      accountId: "bot",
      conversationId: "conversation",
      senderId: "\uFFFD",
    };
    expect(isWellFormedUnicode(route.senderId)).toBe(true);
    expect(toRouteKey(route)).not.toBe(toRouteKey({ ...route, senderId: "?" }));
    expect(() => toRouteKey({ ...route, senderId: "\uD800" })).toThrow(
      "well-formed Unicode",
    );
    expect(
      v2AllowedSenderSchema.safeParse({
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot",
        senderId: "\uFFFD",
      }).success,
    ).toBe(true);
    expect(
      v2AllowedSenderSchema.safeParse({
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot",
        senderId: "\uD800",
      }).success,
    ).toBe(false);
  });

  it("rejects ill-formed Unicode throughout approval scopes", () => {
    const request = {
      requestId: "request",
      identity: {
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot",
        conversationId: "conversation",
        senderId: "sender",
        sessionId: "session",
      },
      scope: {
        kind: "write",
        summary: "Write a file",
        paths: ["personal/file.txt"],
        hosts: ["example.test"],
        commands: ["write"],
      },
      ttlSeconds: 300,
    };
    for (const scope of [
      { ...request.scope, summary: "\uD800" },
      { ...request.scope, paths: ["\uD800"] },
      { ...request.scope, hosts: ["\uD800"] },
      { ...request.scope, commands: ["\uD800"] },
    ]) {
      expect(v2ApprovalRequestSchema.safeParse({ ...request, scope }).success).toBe(
        false,
      );
    }
    expect(
      v2ApprovalRequestSchema.safeParse({
        ...request,
        scope: { ...request.scope, summary: "\uFFFD" },
      }).success,
    ).toBe(true);
  });

  it("recognizes only paths inside the allowed root", () => {
    expect(isPathInside("/repo", "/repo/src/index.ts")).toBe(true);
    expect(isPathInside("/repo", "/other/secret.txt")).toBe(false);
  });
});
