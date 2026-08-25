import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type {
  ChannelContext,
  ChannelHealth,
  ImChannelAdapter,
  ImOutboundMessage,
} from "../src/core/contracts.js";
import { GatewayService } from "../src/daemon/gateway.js";
import {
  startGatewayHttpServer,
  type RunningGatewayServer,
} from "../src/daemon/http-server.js";
import { GatewayStore } from "../src/daemon/store.js";

class MockChannel implements ImChannelAdapter {
  readonly id = "weixin-main";
  readonly kind = "mock";
  readonly sent: ImOutboundMessage[] = [];
  #health: ChannelHealth = { state: "stopped" };

  async start(context: ChannelContext): Promise<void> {
    this.#health = {
      state: "ready",
      since: "2026-08-24T00:00:00.000Z",
    };
    await context.onHealth(this.id, this.#health);
  }

  async stop(): Promise<void> {
    this.#health = { state: "stopped" };
  }

  getHealth(): ChannelHealth {
    return this.#health;
  }

  async send(message: ImOutboundMessage): Promise<void> {
    this.sent.push(message);
  }
}

const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) {
    await cleanup();
  }
});

async function createHarness(): Promise<{
  baseUrl: string;
  token: string;
  channel: MockChannel;
}> {
  const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-http-"));
  const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
  const service = new GatewayService(store);
  const channel = new MockChannel();
  service.registerChannel(channel);
  await service.startChannels();
  const token = "test-token-with-at-least-thirty-two-characters";
  const running = await startGatewayHttpServer({
    service,
    bearerToken: token,
    port: 0,
  });
  cleanups.push(async () => {
    await closeHarness(running, service, store);
    rmSync(directory, { recursive: true, force: true });
  });
  return { baseUrl: running.url, token, channel };
}

async function closeHarness(
  running: RunningGatewayServer,
  service: GatewayService,
  store: GatewayStore,
): Promise<void> {
  await running.close();
  await service.stopChannels();
  store.close();
}

async function request(
  baseUrl: string,
  token: string | undefined,
  pathname: string,
  init: RequestInit = {},
): Promise<Response> {
  return fetch(`${baseUrl}${pathname}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token === undefined ? {} : { Authorization: `Bearer ${token}` }),
      ...init.headers,
    },
  });
}

describe("gateway HTTP API", () => {
  it("requires authentication and enforces personal workspace bindings", async () => {
    const harness = await createHarness();
    expect((await fetch(`${harness.baseUrl}/healthz`)).status).toBe(200);
    expect(
      (await request(harness.baseUrl, undefined, "/v1/status")).status,
    ).toBe(401);

    const workAlias = await request(
      harness.baseUrl,
      harness.token,
      "/v1/workspace-aliases",
      {
        method: "POST",
        body: JSON.stringify({
          alias: "work",
          path: "C:\\work",
          classification: "work",
        }),
      },
    );
    expect(workAlias.status).toBe(200);
    const deniedBinding = await request(
      harness.baseUrl,
      harness.token,
      "/v1/bindings",
      {
        method: "POST",
        body: JSON.stringify({
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot",
          conversationId: "conversation",
          senderId: "sender",
          sessionId: "session",
          workspaceAlias: "work",
        }),
      },
    );
    expect(deniedBinding.status).toBe(403);
  });

  it("accepts, leases, completes, and replies to a paired conversation", async () => {
    const harness = await createHarness();
    const post = (pathname: string, body: unknown) =>
      request(harness.baseUrl, harness.token, pathname, {
        method: "POST",
        body: JSON.stringify(body),
      });
    expect(
      (
        await post("/v1/workspace-aliases", {
          alias: "personal",
          path: process.cwd(),
          classification: "personal",
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await post("/v1/allowed-senders", {
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot",
          senderId: "sender",
        })
      ).status,
    ).toBe(201);
    expect(
      (
        await post("/v1/bindings", {
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot",
          conversationId: "conversation",
          senderId: "sender",
          sessionId: "session",
          workspaceAlias: "personal",
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await post("/v1/inbound", {
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot",
          conversationId: "conversation",
          messageId: "message-1",
          senderId: "sender",
          receivedAt: "2026-08-24T00:00:00.000Z",
          text: "hello",
          attachments: [],
        })
      ).status,
    ).toBe(202);
    const leaseResponse = await post("/v1/messages/lease", {
      sessionId: "session",
      leaseSeconds: 60,
    });
    const leasePayload = (await leaseResponse.json()) as {
      message: { id: number; leaseId: string; message: { text: string } };
    };
    expect(leasePayload.message.message.text).toBe("hello");
    expect(
      (
        await post(`/v1/messages/${leasePayload.message.id}/complete`, {
          leaseId: leasePayload.message.leaseId,
          outcome: "completed",
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await post("/v1/outbound", {
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot",
          conversationId: "conversation",
          senderId: "sender",
          correlationId: "message-1",
          text: "safe response",
        })
      ).status,
    ).toBe(202);
    expect(harness.channel.sent.map((message) => message.text)).toEqual([
      "safe response",
    ]);
  });
});
