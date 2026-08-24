import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { GatewayStore } from "../src/daemon/store.js";

const temporaryDirectories: string[] = [];

function createStore(): GatewayStore {
  const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-store-"));
  temporaryDirectories.push(directory);
  return new GatewayStore(path.join(directory, "gateway.sqlite"));
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("GatewayStore", () => {
  it("deduplicates and leases messages through durable bindings", () => {
    const store = createStore();
    const now = "2026-08-24T00:00:00.000Z";
    store.upsertWorkspaceAlias("personal", "C:\\repo", "personal", now);
    store.upsertBinding(
      {
        channelId: "weixin-main",
        conversationId: "conversation",
        sessionId: "session",
        workspaceAlias: "personal",
      },
      now,
    );
    const message = {
      channelId: "weixin-main",
      conversationId: "conversation",
      messageId: "message-1",
      senderId: "sender",
      receivedAt: now,
      text: "hello",
      attachments: [],
    };
    expect(store.insertInbound(message, now)).toBe(true);
    expect(store.insertInbound(message, now)).toBe(false);

    const leased = store.leaseInbound("session", now, 60);
    expect(leased?.message.text).toBe("hello");
    expect(store.leaseInbound("session", now, 60)).toBeUndefined();
    store.completeInbound(
      leased?.id ?? 0,
      leased?.leaseId ?? "",
      "completed",
    );
    store.close();
  });

  it("binds approval nonces to identity and consumes decisions once", () => {
    const store = createStore();
    const now = "2026-08-24T00:00:00.000Z";
    const identity = {
      channelId: "weixin-main",
      conversationId: "conversation",
      senderId: "sender",
      sessionId: "session",
    };
    store.createApproval({
      requestId: "request",
      nonce: "secure-nonce-value-12345",
      identity,
      scope: {
        kind: "write",
        summary: "Write personal/src/index.ts",
        paths: ["personal/src/index.ts"],
        hosts: [],
        commands: [],
      },
      expiresAt: "2026-08-24T00:05:00.000Z",
      now,
    });
    expect(() =>
      store.decideApproval({
        nonce: "secure-nonce-value-12345",
        identity: { ...identity, senderId: "attacker" },
        decision: "approved",
        now,
      }),
    ).toThrow("does not match");
    expect(
      store.decideApproval({
        nonce: "secure-nonce-value-12345",
        identity,
        decision: "approved",
        now,
      }).status,
    ).toBe("approved");
    expect(store.consumeApproval("request", "session", now)?.status).toBe(
      "approved",
    );
    expect(store.consumeApproval("request", "session", now)?.status).toBe(
      "consumed",
    );
    expect(() =>
      store.decideApproval({
        nonce: "secure-nonce-value-12345",
        identity,
        decision: "approved",
        now,
      }),
    ).toThrow("already");
    store.close();
  });
});
