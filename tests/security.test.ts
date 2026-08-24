import { describe, expect, it } from "vitest";
import {
  chunkOutboundText,
  constantTimeTokenEqual,
  isPathInside,
  redactText,
  SlidingWindowRateLimiter,
  type Clock,
} from "../src/core/security.js";

class MutableClock implements Clock {
  constructor(private timestamp: number) {}

  now(): Date {
    return new Date(this.timestamp);
  }

  advance(milliseconds: number): void {
    this.timestamp += milliseconds;
  }
}

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

  it("enforces a sliding sender rate limit", () => {
    const clock = new MutableClock(1_000);
    const limiter = new SlidingWindowRateLimiter(2, 1_000, clock);
    limiter.consume("sender");
    limiter.consume("sender");
    expect(() => limiter.consume("sender")).toThrow("rate limit");
    clock.advance(1_001);
    expect(() => limiter.consume("sender")).not.toThrow();
  });

  it("recognizes only paths inside the allowed root", () => {
    expect(isPathInside("/repo", "/repo/src/index.ts")).toBe(true);
    expect(isPathInside("/repo", "/other/secret.txt")).toBe(false);
  });
});
