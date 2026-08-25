import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  ChannelContext,
  ImInboundMessage,
} from "../src/core/contracts.js";
import { WeixinAdapter } from "../src/channels/weixin/adapter.js";
import {
  FetchWeixinProtocolClient,
  type WeixinCredentials,
  type WeixinLoginStatus,
  type WeixinProtocolClient,
  type WeixinUpdates,
} from "../src/channels/weixin/protocol.js";
import { GatewayStore } from "../src/daemon/store.js";
import { GatewayError, gatewayErrorCodes } from "../src/core/errors.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  vi.useRealTimers();
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("FetchWeixinProtocolClient", () => {
  it("uses verified iLink endpoints and raw token authorization", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            qrcode: "qr-id",
            qrcode_img_content: "https://example.test/qr",
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            status: "confirmed",
            bot_token: "bot-token",
            ilink_bot_id: "bot-id",
            baseurl: "https://api.example.test",
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ret: 0 }), { status: 200 }),
      );
    const client = new FetchWeixinProtocolClient({
      loginBaseUrl: "https://login.example.test",
      fetch: fetchMock,
    });

    await client.getLoginQr([]);
    await client.pollLoginStatus({
      baseUrl: "https://login.example.test",
      qrCode: "qr-id",
    });
    await client.sendText({
      credentials: {
        botToken: "bot-token",
        botId: "bot-id",
        baseUrl: "https://api.example.test",
      },
      toUserId: "user",
      contextToken: "context",
      text: "hello",
      clientId: "client",
    });

    expect(String(fetchMock.mock.calls[0]?.[0])).toContain(
      "/ilink/bot/get_bot_qrcode?bot_type=3",
    );
    expect(String(fetchMock.mock.calls[1]?.[0])).toContain(
      "/ilink/bot/get_qrcode_status?qrcode=qr-id",
    );
    expect(String(fetchMock.mock.calls[2]?.[0])).toContain(
      "/ilink/bot/sendmessage",
    );
    const sendHeaders = new Headers(fetchMock.mock.calls[2]?.[1]?.headers);
    expect(sendHeaders.get("Authorization")).toBe("bot-token");
    expect(sendHeaders.get("AuthorizationType")).toBe("ilink_bot_token");
    const sendBody = JSON.parse(
      String(fetchMock.mock.calls[2]?.[1]?.body),
    ) as {
      msg: { context_token: string; item_list: Array<{ type: number }> };
    };
    expect(sendBody.msg.context_token).toBe("context");
    expect(sendBody.msg.item_list[0]?.type).toBe(1);
  });

  it("pins ONLINE compatibility and retains empty cursor/timeout updates", async () => {
    const fixture = JSON.parse(
      readFileSync(
        new URL("./fixtures/weixin-online-v1.json", import.meta.url),
        "utf8",
      ),
    ) as {
      name: string;
      endpoints: { updates: string };
      updates: Record<string, unknown>;
    };
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify(fixture.updates), { status: 200 }),
    );
    const client = new FetchWeixinProtocolClient({
      loginBaseUrl: "https://fixture.example.test",
      fetch: fetchMock,
    });
    const updates = await client.getUpdates({
      credentials: {
        botToken: "token",
        botId: "bot",
        baseUrl: "https://fixture.example.test",
      },
      cursor: "previous-cursor",
      desiredTimeoutMs: 12_000,
      signal: new AbortController().signal,
    });
    expect(fixture.name).toBe("weixin-online-v1");
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain(
      fixture.endpoints.updates,
    );
    expect(updates.cursor).toBe("previous-cursor");
    expect(updates.longPollingTimeoutMs).toBe(12_000);
  });

  it("treats protocol and caller abort timeouts as empty polls", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn<typeof fetch>(
      async (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener(
            "abort",
            () => reject(new DOMException("timed out", "AbortError")),
            { once: true },
          );
        }),
    );
    const client = new FetchWeixinProtocolClient({
      loginBaseUrl: "https://fixture.example.test",
      fetch: fetchMock,
    });
    const credentials = {
      botToken: "token",
      botId: "bot",
      baseUrl: "https://fixture.example.test",
    };
    const timed = client.getUpdates({
      credentials,
      cursor: "cursor",
      desiredTimeoutMs: 1_000,
      signal: new AbortController().signal,
    });
    await vi.advanceTimersByTimeAsync(6_000);
    await expect(timed).resolves.toMatchObject({
      messages: [],
      cursor: "cursor",
      longPollingTimeoutMs: 1_000,
    });

    const controller = new AbortController();
    const aborted = client.getUpdates({
      credentials,
      cursor: "cursor",
      desiredTimeoutMs: 2_000,
      signal: controller.signal,
    });
    controller.abort();
    await expect(aborted).resolves.toMatchObject({
      messages: [],
      cursor: "cursor",
    });
    vi.useRealTimers();
  });
});

class FixtureWeixinProtocol implements WeixinProtocolClient {
  readonly sent: Array<{
    toUserId: string;
    contextToken: string;
    text: string;
  }> = [];
  readonly polledBaseUrls: string[] = [];
  #updatesDelivered = false;

  async getLoginQr(): Promise<{
    id: string;
    url: string;
    pollingBaseUrl: string;
  }> {
    return {
      id: "qr-id",
      url: "https://example.test/qr",
      pollingBaseUrl: "https://fixture-login.example.test",
    };
  }

  async pollLoginStatus(input: {
    baseUrl: string;
    qrCode: string;
    verifyCode?: string;
  }): Promise<WeixinLoginStatus> {
    this.polledBaseUrls.push(input.baseUrl);
    return {
      status: "confirmed",
      bot_token: "bot-token",
      ilink_bot_id: "bot-id",
      baseurl: "https://api.example.test",
      ilink_user_id: "owner",
    };
  }

  async getUpdates(input: {
    credentials: WeixinCredentials;
    cursor: string;
    signal: AbortSignal;
  }): Promise<WeixinUpdates> {
    if (!this.#updatesDelivered) {
      this.#updatesDelivered = true;
      return {
        messages: [
          {
            message_id: 42,
            client_id: "message-42",
            from_user_id: "sender",
            message_type: 1,
            create_time_ms: 1_777_000_000_000,
            context_token: "conversation-context",
            item_list: [{ type: 1, text_item: { text: "hello" } }],
          },
        ],
        cursor: "cursor-1",
        longPollingTimeoutMs: 35_000,
      };
    }
    await new Promise<void>((resolve) => {
      input.signal.addEventListener("abort", () => resolve(), { once: true });
    });
    return {
      messages: [],
      cursor: input.cursor,
      longPollingTimeoutMs: 35_000,
    };
  }

  async sendText(input: {
    credentials: WeixinCredentials;
    toUserId: string;
    contextToken: string;
    text: string;
    clientId: string;
  }): Promise<void> {
    this.sent.push({
      toUserId: input.toUserId,
      contextToken: input.contextToken,
      text: input.text,
    });
  }
}

describe("WeixinAdapter", () => {
  it("invalidates an in-flight login confirmation during shutdown", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-stop-race-"));
    temporaryDirectories.push(directory);
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    store.setActiveChannelAccount(
      {
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot-old",
      },
      {
        botToken: "old-token",
        botId: "bot-old",
        baseUrl: "https://old.example.test",
      } satisfies WeixinCredentials,
      "2026-08-24T00:00:00.000Z",
    );
    let resolveStatus:
      | ((status: WeixinLoginStatus) => void)
      | undefined;
    const statusGate = new Promise<WeixinLoginStatus>((resolve) => {
      resolveStatus = resolve;
    });
    const polledAccounts: string[] = [];
    const protocol: WeixinProtocolClient = {
      getLoginQr: async () => ({
        id: "qr",
        url: "https://example.test/qr",
        pollingBaseUrl: "https://example.test",
      }),
      pollLoginStatus: async () => statusGate,
      getUpdates: async (input) => {
        polledAccounts.push(input.credentials.botId);
        await new Promise<void>((resolve) => {
          input.signal.addEventListener("abort", () => resolve(), { once: true });
        });
        return {
          messages: [],
          cursor: input.cursor,
          longPollingTimeoutMs: 35_000,
        };
      },
      sendText: async () => undefined,
    };
    const adapter = new WeixinAdapter({ store, protocol });
    await adapter.start({
      onInbound: async () => undefined,
      onHealth: async () => undefined,
    });
    await adapter.startLogin();
    const confirmation = adapter.pollLogin();
    await adapter.stop();
    resolveStatus?.({
      status: "confirmed",
      bot_token: "new-token",
      ilink_bot_id: "bot-new",
      baseurl: "https://new.example.test",
    });
    await expect(confirmation).resolves.toEqual({ state: "not_started" });
    expect(polledAccounts).toEqual(["bot-old"]);
    expect(adapter.getHealth()).toEqual({ state: "stopped" });
    store.close();
  });

  it("discards a stale QR result after a newer login generation starts", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-login-race-"));
    temporaryDirectories.push(directory);
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    store.setActiveChannelAccount(
      {
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot-old",
      },
      {
        botToken: "old-token",
        botId: "bot-old",
        baseUrl: "https://old.example.test",
      } satisfies WeixinCredentials,
      "2026-08-24T00:00:00.000Z",
    );
    let qrGeneration = 0;
    let resolveStatus:
      | ((status: WeixinLoginStatus) => void)
      | undefined;
    const statusGate = new Promise<WeixinLoginStatus>((resolve) => {
      resolveStatus = resolve;
    });
    const protocol: WeixinProtocolClient = {
      getLoginQr: async () => {
        qrGeneration += 1;
        return {
          id: `qr-${qrGeneration}`,
          url: `https://example.test/qr-${qrGeneration}`,
          pollingBaseUrl: "https://example.test",
        };
      },
      pollLoginStatus: async () => statusGate,
      getUpdates: async (input) => {
        await new Promise<void>((resolve) => {
          input.signal.addEventListener("abort", () => resolve(), { once: true });
        });
        return {
          messages: [],
          cursor: input.cursor,
          longPollingTimeoutMs: 35_000,
        };
      },
      sendText: async () => undefined,
    };
    const adapter = new WeixinAdapter({ store, protocol });
    await adapter.start({
      onInbound: async () => undefined,
      onHealth: async () => undefined,
    });
    await adapter.startLogin();
    const stalePoll = adapter.pollLogin();
    await adapter.startLogin();
    resolveStatus?.({
      status: "confirmed",
      bot_token: "stale-token",
      ilink_bot_id: "bot-stale",
      baseurl: "https://stale.example.test",
    });
    await expect(stalePoll).resolves.toEqual({ state: "not_started" });
    expect(
      store.getActiveChannelAccount<WeixinCredentials>("local", "weixin-main")
        ?.identity.accountId,
    ).toBe("bot-old");

    await adapter.stop();
    store.close();
  });

  it("stops the old account poll before activating a replacement account", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-relogin-"));
    temporaryDirectories.push(directory);
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    store.setActiveChannelAccount(
      {
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot-old",
      },
      {
        botToken: "old-token",
        botId: "bot-old",
        baseUrl: "https://old.example.test",
      } satisfies WeixinCredentials,
      "2026-08-24T00:00:00.000Z",
    );
    const polledAccounts: string[] = [];
    const protocol: WeixinProtocolClient = {
      getLoginQr: async () => ({
        id: "qr",
        url: "https://example.test/qr",
        pollingBaseUrl: "https://example.test",
      }),
      pollLoginStatus: async () => ({
        status: "confirmed",
        bot_token: "new-token",
        ilink_bot_id: "bot-new",
        baseurl: "https://new.example.test",
      }),
      getUpdates: async (input) => {
        polledAccounts.push(input.credentials.botId);
        await new Promise<void>((resolve) => {
          input.signal.addEventListener("abort", () => resolve(), { once: true });
        });
        return {
          messages: [],
          cursor: input.cursor,
          longPollingTimeoutMs: 35_000,
        };
      },
      sendText: async () => undefined,
    };
    const adapter = new WeixinAdapter({ store, protocol });
    await adapter.start({
      onInbound: async () => undefined,
      onHealth: async () => undefined,
    });
    await vi.waitFor(() => expect(polledAccounts).toEqual(["bot-old"]));
    await adapter.startLogin();
    await adapter.pollLogin();
    await vi.waitFor(() =>
      expect(polledAccounts).toEqual(["bot-old", "bot-new"]),
    );

    await adapter.stop();
    store.close();
  });

  it("advances the cursor after a durable terminal admission rejection", async () => {
    vi.useFakeTimers();
    const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-drop-"));
    temporaryDirectories.push(directory);
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    store.setActiveChannelAccount(
      {
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot-id",
      },
      {
        botToken: "bot-token",
        botId: "bot-id",
        baseUrl: "https://api.example.test",
      } satisfies WeixinCredentials,
      "2026-08-24T00:00:00.000Z",
    );
    let delivered = false;
    const protocol: WeixinProtocolClient = {
      getLoginQr: async () => ({
        id: "qr",
        url: "https://example.test/qr",
        pollingBaseUrl: "https://example.test",
      }),
      pollLoginStatus: async () => ({ status: "wait" }),
      getUpdates: async (input) => {
        if (!delivered) {
          delivered = true;
          return {
            messages: [
              {
                message_id: 1,
                from_user_id: "sender",
                message_type: 1,
                context_token: "context",
                item_list: [{ type: 1, text_item: { text: "denied" } }],
              },
            ],
            cursor: "cursor-after-denial",
            longPollingTimeoutMs: 35_000,
          };
        }
        await new Promise<void>((resolve) => {
          input.signal.addEventListener("abort", () => resolve(), { once: true });
        });
        return {
          messages: [],
          cursor: input.cursor,
          longPollingTimeoutMs: 35_000,
        };
      },
      sendText: async () => undefined,
    };
    const adapter = new WeixinAdapter({ store, protocol });
    await adapter.start({
      onInbound: async () => {
        throw new GatewayError({
          code: gatewayErrorCodes.senderDenied,
          message: "denied",
          status: 403,
        });
      },
      onHealth: async () => undefined,
    });
    await vi.advanceTimersByTimeAsync(1);
    expect(
      store.getChannelState<string>(
        {
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot-id",
        },
        "updates-cursor",
      ),
    ).toBe("cursor-after-denial");
    await adapter.stop();
    store.close();
    vi.useRealTimers();
  });

  it("isolates cursor and context state by negotiated account", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-state-"));
    temporaryDirectories.push(directory);
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    const first = {
      tenantId: "local" as const,
      channelId: "weixin-main",
      accountId: "bot-a",
    };
    const second = { ...first, accountId: "bot-b" };
    store.setChannelState(first, "updates-cursor", "cursor-a", new Date().toISOString());
    store.setChannelState(second, "updates-cursor", "cursor-b", new Date().toISOString());
    expect(store.getChannelState(first, "updates-cursor")).toBe("cursor-a");
    expect(store.getChannelState(second, "updates-cursor")).toBe("cursor-b");
    store.close();
  });

  it("persists login, normalizes inbound messages, and echoes context tokens", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-weixin-"));
    temporaryDirectories.push(directory);
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    const protocol = new FixtureWeixinProtocol();
    let cleanupAdapter: WeixinAdapter | undefined;
    const inbound = new Promise<ImInboundMessage>((resolve) => {
      const context: ChannelContext = {
        onInbound: async (envelope) => resolve(await envelope.materialize()),
        onHealth: async () => undefined,
      };
      const adapter = new WeixinAdapter({ store, protocol });
      void adapter.start(context).then(async () => {
        await adapter.startLogin();
        await adapter.pollLogin();
      });
      cleanupAdapter = adapter;
    });
    const message = await inbound;
    expect(message.text).toBe("hello");
    expect(message.conversationId).toBe("sender");
    expect(protocol.polledBaseUrls).toEqual([
      "https://fixture-login.example.test",
    ]);
    await cleanupAdapter?.send({
      tenantId: "local",
      channelId: "weixin-main",
      accountId: "bot-id",
      conversationId: "sender",
      senderId: "sender",
      correlationId: "message-42",
      text: "response",
      format: "plain",
      final: true,
    });
    expect(protocol.sent).toEqual([
      {
        toUserId: "sender",
        contextToken: "conversation-context",
        text: "response",
      },
    ]);
    await cleanupAdapter?.stop();
    store.close();
  });

  it("does not advance the update cursor when batch processing fails", async () => {
    vi.useFakeTimers();
    const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-cursor-"));
    temporaryDirectories.push(directory);
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    store.setActiveChannelAccount(
      {
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot-id",
      },
      {
        botToken: "bot-token",
        botId: "bot-id",
        baseUrl: "https://api.example.test",
      } satisfies WeixinCredentials,
      "2026-08-24T00:00:00.000Z",
    );
    const cursors: string[] = [];
    let calls = 0;
    const protocol: WeixinProtocolClient = {
      getLoginQr: async () => ({
        id: "qr",
        url: "https://example.test/qr",
        pollingBaseUrl: "https://example.test",
      }),
      pollLoginStatus: async () => ({ status: "wait" }),
      getUpdates: async (input) => {
        cursors.push(input.cursor);
        calls += 1;
        if (calls === 1) {
          return {
            messages: [
              {
                message_id: 1,
                from_user_id: "sender",
                message_type: 1,
                context_token: "context",
                item_list: [{ type: 1, text_item: { text: "fail" } }],
              },
            ],
            cursor: "cursor-after-batch",
            longPollingTimeoutMs: 35_000,
          };
        }
        await new Promise<void>((resolve) => {
          input.signal.addEventListener("abort", () => resolve(), {
            once: true,
          });
        });
        return {
          messages: [],
          cursor: input.cursor,
          longPollingTimeoutMs: 35_000,
        };
      },
      sendText: async () => undefined,
    };
    const adapter = new WeixinAdapter({ store, protocol });
    await adapter.start({
      onInbound: async () => {
        throw new Error("transient inbound failure");
      },
      onHealth: async () => undefined,
    });
    await vi.advanceTimersByTimeAsync(2_000);
    expect(cursors).toEqual(["", ""]);
    expect(
      store.getChannelState<string>(
        {
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot-id",
        },
        "updates-cursor",
      ),
    ).toBeUndefined();
    await adapter.stop();
    store.close();
    vi.useRealTimers();
  });
});
