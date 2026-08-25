import { mkdtempSync, rmSync } from "node:fs";
import { createHmac } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { canonicalizeIdentityComponents } from "../src/core/contracts.js";
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
      accountLabel: "bot-account",
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

async function createHarness(
  onShutdown?: () => Promise<void> | void,
  shutdownProtocolDependencies?: {
    now?: () => number;
    createId?: () => string;
  },
): Promise<{
  baseUrl: string;
  token: string;
  channel: MockChannel;
  store: GatewayStore;
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
    ...(onShutdown === undefined ? {} : { onShutdown }),
    ...(shutdownProtocolDependencies === undefined
      ? {}
      : { shutdownProtocolDependencies }),
  });
  cleanups.push(async () => {
    await closeHarness(running, service, store);
    rmSync(directory, { recursive: true, force: true });
  });
  return { baseUrl: running.url, token, channel, store };
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

interface ShutdownOwner {
  pid: number;
  creationMarker: string;
  executablePath: string;
  entrypoint: string;
}

interface ShutdownIdentity {
  protocolVersion: 1;
  apiVersion: number;
  capabilities: string[];
  instanceId: string;
  challengeId: string;
  owner: ShutdownOwner;
  port: number;
  clientNonce: string;
  expiresAt: number;
  responseProof: string;
}

function shutdownProof(
  token: string,
  purpose: "identity-request" | "identity-response",
  values: readonly string[],
): string {
  return createHmac("sha256", token)
    .update(
      canonicalizeIdentityComponents([
        "copilot-im-gateway-shutdown",
        "1",
        purpose,
        ...values,
      ]),
      "utf8",
    )
    .digest("hex");
}

function shutdownOwner(): ShutdownOwner {
  return {
    pid: process.pid,
    creationMarker: "133713371337000000",
    executablePath: process.execPath,
    entrypoint: path.resolve("dist", "daemon", "main.js"),
  };
}

async function requestShutdownIdentity(options: {
  baseUrl: string;
  token: string;
  clientNonce?: string;
  owner?: ShutdownOwner;
  port?: number;
}): Promise<{ requestBody: object; response: Response }> {
  const owner = options.owner ?? shutdownOwner();
  const port = options.port ?? Number(new URL(options.baseUrl).port);
  const clientNonce = options.clientNonce ?? "a".repeat(64);
  const requestProof = shutdownProof(options.token, "identity-request", [
    String(owner.pid),
    owner.creationMarker,
    String(port),
    clientNonce,
    owner.executablePath,
    owner.entrypoint,
  ]);
  const requestBody = {
    protocolVersion: 1,
    owner,
    port,
    clientNonce,
    requestProof,
  };
  return {
    requestBody,
    response: await request(
      options.baseUrl,
      undefined,
      "/v2/admin/identity",
      {
        method: "POST",
        body: JSON.stringify(requestBody),
      },
    ),
  };
}

function shutdownCredentials(identity: ShutdownIdentity): object {
  return {
    protocolVersion: identity.protocolVersion,
    instanceId: identity.instanceId,
    challengeId: identity.challengeId,
    clientNonce: identity.clientNonce,
    responseProof: identity.responseProof,
  };
}

describe("gateway HTTP API", () => {
  it("binds and consumes an authenticated shutdown challenge exactly once", async () => {
    let now = Date.parse("2026-08-25T00:00:00.000Z");
    let callbackCalls = 0;
    let observeShutdown: () => void = () => undefined;
    const shutdownObserved = new Promise<void>((resolve) => {
      observeShutdown = resolve;
    });
    const harness = await createHarness(
      () => {
        callbackCalls += 1;
        observeShutdown();
      },
      { now: () => now },
    );
    const identityResponse = await requestShutdownIdentity(harness);
    expect(identityResponse.response.status).toBe(200);
    const identity = (await identityResponse.response.json()) as ShutdownIdentity;
    expect(identity).toMatchObject({
      protocolVersion: 1,
      apiVersion: 2,
      capabilities: expect.arrayContaining(["reservation-ownership"]),
      owner: shutdownOwner(),
      port: Number(new URL(harness.baseUrl).port),
      clientNonce: "a".repeat(64),
      expiresAt: expect.any(Number),
      instanceId: expect.any(String),
      challengeId: expect.any(String),
      responseProof: expect.any(String),
    });
    expect(identity.responseProof).toBe(
      shutdownProof(harness.token, "identity-response", [
        String(identity.apiVersion),
        identity.instanceId,
        identity.challengeId,
        String(identity.owner.pid),
        identity.owner.creationMarker,
        String(identity.port),
        identity.clientNonce,
        String(identity.expiresAt),
        identity.owner.executablePath,
        identity.owner.entrypoint,
      ]),
    );
    const credentials = shutdownCredentials(identity);

    const unauthenticated = await request(
      harness.baseUrl,
      undefined,
      "/v2/admin/shutdown",
      { method: "POST", body: JSON.stringify(credentials) },
    );
    expect(unauthenticated.status).toBe(401);
    expect(callbackCalls).toBe(0);

    const bodyRejected = await request(
      harness.baseUrl,
      harness.token,
      "/v2/admin/shutdown",
      { method: "POST", body: "{}" },
    );
    expect(bodyRejected.status).toBe(400);
    expect(callbackCalls).toBe(0);

    const accepted = await request(
      harness.baseUrl,
      harness.token,
      "/v2/admin/shutdown",
      { method: "POST", body: JSON.stringify(credentials) },
    );
    expect(accepted.status).toBe(202);
    expect(await accepted.json()).toEqual({ accepted: true });
    await shutdownObserved;

    now += 10_000;
    const repeated = await request(
      harness.baseUrl,
      harness.token,
      "/v2/admin/shutdown",
      { method: "POST", body: JSON.stringify(credentials) },
    );
    expect(repeated.status).toBe(409);
    expect(await repeated.json()).toMatchObject({
      error: { code: "SHUTDOWN_CHALLENGE_ALREADY_CONSUMED" },
    });
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
    expect(callbackCalls).toBe(1);
  });

  it("rejects forged, stale, duplicate, and cross-instance shutdown identity", async () => {
    let secondShutdownCalls = 0;
    const first = await createHarness();
    const second = await createHarness(() => {
      secondShutdownCalls += 1;
    });
    const firstOwner = shutdownOwner();

    const forgedProof = await requestShutdownIdentity({
      baseUrl: first.baseUrl,
      token: "wrong-token-with-at-least-thirty-two-characters",
      clientNonce: "b".repeat(64),
    });
    expect(forgedProof.response.status).toBe(401);

    const wrongPid = await requestShutdownIdentity({
      ...first,
      owner: { ...firstOwner, pid: process.pid + 1 },
      clientNonce: "e".repeat(64),
    });
    expect(wrongPid.response.status).toBe(401);

    const valid = await requestShutdownIdentity({
      ...first,
      clientNonce: "c".repeat(64),
    });
    expect(valid.response.status).toBe(200);
    const identity = (await valid.response.json()) as ShutdownIdentity;

    const duplicate = await request(
      first.baseUrl,
      undefined,
      "/v2/admin/identity",
      {
        method: "POST",
        body: JSON.stringify(valid.requestBody),
      },
    );
    expect(duplicate.status).toBe(409);
    expect(await duplicate.json()).toMatchObject({
      error: { code: "SHUTDOWN_CHALLENGE_ALREADY_CONSUMED" },
    });

    const crossInstance = await request(
      second.baseUrl,
      second.token,
      "/v2/admin/shutdown",
      {
        method: "POST",
        body: JSON.stringify(shutdownCredentials(identity)),
      },
    );
    expect(crossInstance.status).toBe(401);
    expect(await crossInstance.json()).toMatchObject({
      error: { code: "SHUTDOWN_CHALLENGE_INVALID" },
    });
    expect(secondShutdownCalls).toBe(0);
  });

  it("expires shutdown challenges without scheduling shutdown", async () => {
    let now = Date.parse("2026-08-25T00:00:00.000Z");
    let shutdownCalls = 0;
    const ids = [
      "11111111-1111-4111-8111-111111111111",
      "22222222-2222-4222-8222-222222222222",
    ];
    const harness = await createHarness(
      () => {
        shutdownCalls += 1;
      },
      {
        now: () => now,
        createId: () => ids.shift() ?? "33333333-3333-4333-8333-333333333333",
      },
    );
    const issued = await requestShutdownIdentity({
      ...harness,
      clientNonce: "d".repeat(64),
    });
    const identity = (await issued.response.json()) as ShutdownIdentity;
    expect(identity.expiresAt).toBe(Date.parse("2026-08-25T00:00:10.000Z"));

    now += 10_000;
    const expired = await request(
      harness.baseUrl,
      harness.token,
      "/v2/admin/shutdown",
      {
        method: "POST",
        body: JSON.stringify(shutdownCredentials(identity)),
      },
    );
    expect(expired.status).toBe(409);
    expect(await expired.json()).toMatchObject({
      error: { code: "SHUTDOWN_CHALLENGE_EXPIRED" },
    });

    const replayedIdentity = await request(
      harness.baseUrl,
      undefined,
      "/v2/admin/identity",
      {
        method: "POST",
        body: JSON.stringify(issued.requestBody),
      },
    );
    expect(replayedIdentity.status).toBe(409);
    expect(await replayedIdentity.json()).toMatchObject({
      error: { code: "SHUTDOWN_CHALLENGE_ALREADY_CONSUMED" },
    });
    expect(shutdownCalls).toBe(0);
  });

  it("preserves replay tombstones and fails closed at shutdown challenge capacity", async () => {
    const harness = await createHarness(undefined, {
      now: () => Date.parse("2026-08-25T00:00:00.000Z"),
    });
    const issuedRequests: object[] = [];
    for (let index = 1; index <= 64; index += 1) {
      const issued = await requestShutdownIdentity({
        ...harness,
        clientNonce: index.toString(16).padStart(64, "0"),
      });
      expect(issued.response.status).toBe(200);
      issuedRequests.push(issued.requestBody);
    }

    const replay = await request(
      harness.baseUrl,
      undefined,
      "/v2/admin/identity",
      {
        method: "POST",
        body: JSON.stringify(issuedRequests[0]),
      },
    );
    expect(replay.status).toBe(409);
    expect(await replay.json()).toMatchObject({
      error: { code: "SHUTDOWN_CHALLENGE_ALREADY_CONSUMED" },
    });

    const capacity = await requestShutdownIdentity({
      ...harness,
      clientNonce: "65".padStart(64, "0"),
    });
    expect(capacity.response.status).toBe(503);
    expect(await capacity.response.json()).toMatchObject({
      error: {
        code: "SHUTDOWN_CHALLENGE_CAPACITY_EXCEEDED",
        retryable: true,
      },
    });
  });

  it("requires authentication and enforces personal workspace bindings", async () => {
    const harness = await createHarness();
    expect((await fetch(`${harness.baseUrl}/healthz`)).status).toBe(200);
    expect(
      (await request(harness.baseUrl, undefined, "/v1/status")).status,
    ).toBe(401);
    const handshake = await request(
      harness.baseUrl,
      harness.token,
      "/v2/status",
    );
    expect(await handshake.json()).toMatchObject({
      apiVersion: 2,
      capabilities: expect.arrayContaining([
        "account-scoped-routing",
        "reservation-ownership",
      ]),
    });

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
      "/v2/bindings",
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

    const legacyUnsafe = await request(
      harness.baseUrl,
      harness.token,
      "/v1/bindings",
      {
        method: "POST",
        body: JSON.stringify({
          channelId: "weixin-main",
          conversationId: "conversation",
          sessionId: "session",
          workspaceAlias: "work",
        }),
      },
    );
    expect(legacyUnsafe.status).toBe(426);
    expect(await legacyUnsafe.json()).toMatchObject({
      error: { code: "UPGRADE_REQUIRED" },
    });
    expect(
      (
        await request(
          harness.baseUrl,
          harness.token,
          "/v1/messages/lease",
          {
            method: "POST",
            body: JSON.stringify({ sessionId: "session" }),
          },
        )
      ).status,
    ).toBe(426);
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
        await post("/v2/workspace-aliases", {
          alias: "personal",
          path: process.cwd(),
          classification: "personal",
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await post("/v2/allowed-senders", {
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot",
          senderId: "sender",
        })
      ).status,
    ).toBe(201);
    expect(
      (
        await post("/v2/bindings", {
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
        await post("/v2/inbound", {
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
    const leaseResponse = await post("/v2/messages/lease", {
      sessionId: "session",
      leaseSeconds: 60,
    });
    const leasePayload = (await leaseResponse.json()) as {
      message: { id: number; leaseId: string; message: { text: string } };
    };
    expect(leasePayload.message.message.text).toBe("hello");
    expect(
      (
        await post(`/v2/messages/${leasePayload.message.id}/complete`, {
          leaseId: leasePayload.message.leaseId,
          outcome: "completed",
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await post("/v2/outbound", {
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

  it("exposes only safe login identity and validates Unicode identifiers", async () => {
    const harness = await createHarness();
    harness.store.setActiveChannelAccount(
      {
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot-account",
      },
      {
        botToken: "credential-that-must-never-leak",
        botId: "bot-account",
        baseUrl: "https://service.invalid",
        userId: "personal-user",
      },
      "2026-08-24T00:00:00.000Z",
    );
    const status = await request(
      harness.baseUrl,
      harness.token,
      "/v2/status",
    ).then((response) => response.json());
    expect(status).toMatchObject({
      channels: [
        {
          health: { state: "ready", accountLabel: "bot-account" },
          login: { accountId: "bot-account", userId: "personal-user" },
        },
      ],
    });
    expect(JSON.stringify(status)).not.toContain("credential-that-must-never-leak");
    expect(JSON.stringify(status)).not.toContain("service.invalid");

    const postSender = (senderId: string) =>
      request(harness.baseUrl, harness.token, "/v2/allowed-senders", {
        method: "POST",
        body: JSON.stringify({
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot-account",
          senderId,
        }),
      });
    expect((await postSender("\uD800")).status).toBe(400);
    expect((await postSender("\uFFFD")).status).toBe(201);
  });

  it("returns a validation error for ill-formed approval scope Unicode", async () => {
    const harness = await createHarness();
    const response = await request(
      harness.baseUrl,
      harness.token,
      "/v2/approvals",
      {
        method: "POST",
        body: JSON.stringify({
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
            summary: "\uD800",
            paths: [],
            hosts: [],
            commands: [],
          },
          ttlSeconds: 300,
        }),
      },
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      error: { code: "INVALID_INPUT" },
    });
  });
});
