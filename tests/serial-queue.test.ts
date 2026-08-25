import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { GatewayService } from "../src/daemon/gateway.js";
import { GatewayStore } from "../src/daemon/store.js";

describe("minimal inbound authorization", () => {
  it("denies before materialization, binding, context, or inbox side effects", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "gateway-authz-"));
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    const service = new GatewayService(store);
    const materialize = vi.fn(async () => {
      throw new Error("rejected content must never be materialized");
    });
    const binding = vi.spyOn(store, "getBinding");
    const finalize = vi.spyOn(store, "finalizeInbound");
    const context = vi.spyOn(store, "setChannelState");

    await expect(
      service.onInbound({
        identity: {
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot-secret",
          conversationId: "conversation-secret",
          senderId: "sender-secret",
        },
        messageId: "message-secret",
        receivedAt: "2026-08-24T00:00:00.000Z",
        materialize,
      }),
    ).rejects.toMatchObject({ code: "SENDER_NOT_ALLOWED" });
    expect(materialize).not.toHaveBeenCalled();
    expect(binding).not.toHaveBeenCalled();
    expect(finalize).not.toHaveBeenCalled();
    expect(context).not.toHaveBeenCalled();
    const denial = store.listAudit().find(
      (event) => event.eventType === "inbound.sender.denied",
    );
    expect(JSON.stringify(denial)).not.toContain("secret");

    store.close();
    rmSync(directory, { recursive: true, force: true });
  });

  it("rejects an allowed but unbound route before materialization", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "gateway-binding-"));
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    const service = new GatewayService(store);
    const route = {
      tenantId: "local" as const,
      channelId: "weixin-main",
      accountId: "bot",
      conversationId: "conversation",
      senderId: "sender",
    };
    store.allowSender(route, undefined, "2026-08-24T00:00:00.000Z");
    const materialize = vi.fn(async () => ({
      ...route,
      messageId: "message",
      receivedAt: "2026-08-24T00:00:00.000Z",
      text: "must remain unread",
      attachments: [],
    }));

    await expect(
      service.onInbound({
        identity: route,
        messageId: "message",
        receivedAt: "2026-08-24T00:00:00.000Z",
        materialize,
      }),
    ).rejects.toMatchObject({ code: "WORKSPACE_NOT_ALLOWED" });
    expect(materialize).not.toHaveBeenCalled();
    expect(
      store.listAudit().some((event) => event.eventType === "inbound.route.denied"),
    ).toBe(true);

    store.close();
    rmSync(directory, { recursive: true, force: true });
  });

  it("keeps an earlier materializing turn ahead of a later finalized turn", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "gateway-fifo-"));
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    const now = "2026-08-24T00:00:00.000Z";
    const service = new GatewayService(store, {
      now: () => new Date(now),
    });
    const route = {
      tenantId: "local" as const,
      channelId: "weixin-main",
      accountId: "bot",
      conversationId: "conversation",
      senderId: "sender",
    };
    store.upsertWorkspaceAlias("personal", process.cwd(), "personal", now);
    store.allowSender(route, undefined, now);
    store.upsertBinding(
      { ...route, sessionId: "session", workspaceAlias: "personal" },
      now,
    );
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const first = service.onInbound({
      identity: route,
      messageId: "first",
      receivedAt: now,
      materialize: async () => {
        await gate;
        return {
          ...route,
          messageId: "first",
          receivedAt: now,
          text: "first",
          attachments: [],
        };
      },
    });
    await service.onInbound({
      identity: route,
      messageId: "second",
      receivedAt: now,
      materialize: async () => ({
        ...route,
        messageId: "second",
        receivedAt: now,
        text: "second",
        attachments: [],
      }),
    });
    expect(store.leaseInbound("session", now, 60)).toBeUndefined();
    release?.();
    await first;
    expect(store.leaseInbound("session", now, 60)?.message.messageId).toBe(
      "first",
    );

    store.close();
    rmSync(directory, { recursive: true, force: true });
  });
});
