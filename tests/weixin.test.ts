import { mkdtempSync, rmSync } from "node:fs";
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
  it("persists login, normalizes inbound messages, and echoes context tokens", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-weixin-"));
    temporaryDirectories.push(directory);
    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    const protocol = new FixtureWeixinProtocol();
    let cleanupAdapter: WeixinAdapter | undefined;
    const inbound = new Promise<ImInboundMessage>((resolve) => {
      const context: ChannelContext = {
        onInbound: async (message) => resolve(message),
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
      channelId: "weixin-main",
      conversationId: "sender",
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
    store.setChannelState(
      "weixin-main",
      "credentials",
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
      store.getChannelState<string>("weixin-main", "updates-cursor"),
    ).toBeUndefined();
    await adapter.stop();
    store.close();
    vi.useRealTimers();
  });
});
