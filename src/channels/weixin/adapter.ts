import { randomUUID } from "node:crypto";
import type {
  ChannelContext,
  ChannelHealth,
  ChannelLoginSnapshot,
  ImOutboundMessage,
  LoginCapableChannelAdapter,
} from "../../core/contracts.js";
import type { Clock } from "../../core/security.js";
import { systemClock } from "../../core/security.js";
import type { GatewayStore } from "../../daemon/store.js";
import type {
  WeixinCredentials,
  WeixinLoginStatus,
  WeixinMessage,
  WeixinProtocolClient,
} from "./protocol.js";

interface ActiveLogin {
  qrCode: string;
  qrCodeUrl: string;
  pollingBaseUrl: string;
  startedAt: number;
}

export interface WeixinAdapterOptions {
  id?: string;
  store: GatewayStore;
  protocol: WeixinProtocolClient;
  clock?: Clock;
}

export class WeixinAdapter implements LoginCapableChannelAdapter {
  readonly id: string;
  readonly kind = "weixin-ilink";
  readonly #store: GatewayStore;
  readonly #protocol: WeixinProtocolClient;
  readonly #clock: Clock;
  #context: ChannelContext | undefined;
  #credentials: WeixinCredentials | undefined;
  #health: ChannelHealth = { state: "stopped" };
  #login: ActiveLogin | undefined;
  #pollController: AbortController | undefined;
  #pollTask: Promise<void> | undefined;

  constructor(options: WeixinAdapterOptions) {
    this.id = options.id ?? "weixin-main";
    this.#store = options.store;
    this.#protocol = options.protocol;
    this.#clock = options.clock ?? systemClock;
  }

  getHealth(): ChannelHealth {
    return this.#health;
  }

  async start(context: ChannelContext): Promise<void> {
    this.#context = context;
    this.#credentials = this.#store.getChannelState<WeixinCredentials>(
      this.id,
      "credentials",
    );
    if (this.#credentials === undefined) {
      await this.#setHealth({
        state: "awaiting_login",
        since: this.#clock.now().toISOString(),
      });
      return;
    }
    await this.#startPolling();
  }

  async stop(): Promise<void> {
    this.#pollController?.abort();
    await this.#pollTask;
    this.#pollTask = undefined;
    this.#pollController = undefined;
    await this.#setHealth({ state: "stopped" });
  }

  async startLogin(): Promise<ChannelLoginSnapshot> {
    const localTokens =
      this.#credentials === undefined ? [] : [this.#credentials.botToken];
    const qr = await this.#protocol.getLoginQr(localTokens);
    this.#login = {
      qrCode: qr.id,
      qrCodeUrl: qr.url,
      pollingBaseUrl: "https://ilinkai.weixin.qq.com",
      startedAt: this.#clock.now().getTime(),
    };
    await this.#setHealth({
      state: "awaiting_login",
      since: this.#clock.now().toISOString(),
      qrCodeUrl: qr.url,
    });
    return { state: "waiting", qrCodeUrl: qr.url };
  }

  async pollLogin(verifyCode?: string): Promise<ChannelLoginSnapshot> {
    const login = this.#login;
    if (login === undefined) {
      return { state: "not_started" };
    }
    if (this.#clock.now().getTime() - login.startedAt > 5 * 60_000) {
      this.#login = undefined;
      return { state: "expired" };
    }
    const status = await this.#protocol.pollLoginStatus({
      baseUrl: login.pollingBaseUrl,
      qrCode: login.qrCode,
      ...(verifyCode === undefined ? {} : { verifyCode }),
    });
    return this.#applyLoginStatus(status);
  }

  async #applyLoginStatus(
    status: WeixinLoginStatus,
  ): Promise<ChannelLoginSnapshot> {
    const login = this.#login;
    if (login === undefined) {
      return { state: "not_started" };
    }
    switch (status.status) {
      case "wait":
        return { state: "waiting", qrCodeUrl: login.qrCodeUrl };
      case "scaned":
        return { state: "scanned", qrCodeUrl: login.qrCodeUrl };
      case "need_verifycode":
        return {
          state: "verification_required",
          qrCodeUrl: login.qrCodeUrl,
        };
      case "scaned_but_redirect":
        if (status.redirect_host !== undefined) {
          login.pollingBaseUrl = `https://${status.redirect_host}`;
        }
        return { state: "scanned", qrCodeUrl: login.qrCodeUrl };
      case "expired":
        this.#login = undefined;
        return { state: "expired" };
      case "verify_code_blocked":
        this.#login = undefined;
        return { state: "blocked" };
      case "binded_redirect":
        this.#login = undefined;
        if (this.#credentials !== undefined) {
          await this.#startPolling();
          return {
            state: "confirmed",
            accountId: this.#credentials.botId,
            ...(this.#credentials.userId === undefined
              ? {}
              : { userId: this.#credentials.userId }),
          };
        }
        return { state: "expired" };
      case "confirmed": {
        if (
          status.bot_token === undefined ||
          status.ilink_bot_id === undefined ||
          status.baseurl === undefined
        ) {
          throw new Error(
            "Weixin login confirmation did not include required credentials.",
          );
        }
        this.#credentials = {
          botToken: status.bot_token,
          botId: status.ilink_bot_id,
          baseUrl: status.baseurl,
          ...(status.ilink_user_id === undefined
            ? {}
            : { userId: status.ilink_user_id }),
        };
        this.#store.setChannelState(
          this.id,
          "credentials",
          this.#credentials,
          this.#clock.now().toISOString(),
        );
        this.#login = undefined;
        await this.#startPolling();
        return {
          state: "confirmed",
          accountId: status.ilink_bot_id,
          ...(status.ilink_user_id === undefined
            ? {}
            : { userId: status.ilink_user_id }),
        };
      }
    }
  }

  async send(message: ImOutboundMessage): Promise<void> {
    if (this.#credentials === undefined) {
      throw new Error("Weixin channel is not logged in.");
    }
    const contextToken = this.#store.getChannelState<string>(
      this.id,
      `context:${message.conversationId}`,
    );
    if (contextToken === undefined) {
      throw new Error(
        "Weixin conversation has no context token; receive a message before replying.",
      );
    }
    await this.#protocol.sendText({
      credentials: this.#credentials,
      toUserId: message.conversationId,
      contextToken,
      text: message.text,
      clientId: randomUUID(),
    });
  }

  async #startPolling(): Promise<void> {
    if (this.#credentials === undefined || this.#pollTask !== undefined) {
      return;
    }
    this.#pollController = new AbortController();
    await this.#setHealth({
      state: "starting",
      since: this.#clock.now().toISOString(),
    });
    this.#pollTask = this.#pollLoop(
      this.#credentials,
      this.#pollController.signal,
    ).finally(() => {
      this.#pollTask = undefined;
    });
    await this.#setHealth({
      state: "ready",
      since: this.#clock.now().toISOString(),
      accountLabel: this.#credentials.botId,
    });
  }

  async #pollLoop(
    credentials: WeixinCredentials,
    signal: AbortSignal,
  ): Promise<void> {
    let cursor =
      this.#store.getChannelState<string>(this.id, "updates-cursor") ?? "";
    let retryMs = 2_000;
    while (!signal.aborted) {
      try {
        const updates = await this.#protocol.getUpdates({
          credentials,
          cursor,
          signal,
        });
        if (signal.aborted) {
          return;
        }
        if (updates.errorCode === -14) {
          this.#credentials = undefined;
          await this.#setHealth({
            state: "awaiting_login",
            since: this.#clock.now().toISOString(),
          });
          return;
        }
        if (updates.errorCode !== undefined && updates.errorCode !== 0) {
          throw new Error(
            `Weixin getUpdates error ${updates.errorCode}: ${updates.errorMessage ?? "unknown"}`,
          );
        }
        if (updates.cursor !== cursor) {
          cursor = updates.cursor;
          this.#store.setChannelState(
            this.id,
            "updates-cursor",
            cursor,
            this.#clock.now().toISOString(),
          );
        }
        for (const message of updates.messages) {
          await this.#acceptMessage(message);
        }
        retryMs = 2_000;
        await sleep(updates.messages.length > 0 ? 100 : 300, signal);
      } catch (error) {
        if (signal.aborted) {
          return;
        }
        await this.#setHealth({
          state: "degraded",
          since: this.#clock.now().toISOString(),
          errorCode: "WEIXIN_POLL_FAILED",
        });
        console.error("Weixin long-poll failed", error);
        await sleep(retryMs, signal);
        retryMs = Math.min(30_000, retryMs * 2);
      }
    }
  }

  async #acceptMessage(message: WeixinMessage): Promise<void> {
    if (
      message.message_type !== 1 ||
      message.from_user_id === undefined ||
      message.context_token === undefined
    ) {
      return;
    }
    const text = (message.item_list ?? [])
      .flatMap((item) => [
        item.text_item?.text,
        item.voice_item?.text,
      ])
      .filter((value): value is string => value !== undefined)
      .join("\n")
      .trim();
    const attachments = (message.item_list ?? []).flatMap((item, index) => {
      if (item.image_item !== undefined) {
        return [
          {
            id: item.msg_id ?? `image-${index}`,
            mediaType: "image/*",
            ...(item.image_item.mid_size === undefined
              ? {}
              : { sizeBytes: item.image_item.mid_size }),
          },
        ];
      }
      if (item.file_item !== undefined) {
        const size = Number(item.file_item.len);
        return [
          {
            id: item.msg_id ?? `file-${index}`,
            mediaType: "application/octet-stream",
            ...(Number.isFinite(size) ? { sizeBytes: size } : {}),
            ...(item.file_item.file_name === undefined
              ? {}
              : { fileName: item.file_item.file_name }),
          },
        ];
      }
      if (item.video_item !== undefined) {
        return [
          {
            id: item.msg_id ?? `video-${index}`,
            mediaType: "video/*",
            ...(item.video_item.video_size === undefined
              ? {}
              : { sizeBytes: item.video_item.video_size }),
          },
        ];
      }
      return [];
    });
    if (text.length === 0 && attachments.length === 0) {
      return;
    }
    this.#store.setChannelState(
      this.id,
      `context:${message.from_user_id}`,
      message.context_token,
      this.#clock.now().toISOString(),
    );
    await this.#context?.onInbound({
      channelId: this.id,
      conversationId: message.from_user_id,
      messageId:
        message.client_id ??
        String(message.message_id ?? `${message.create_time_ms ?? 0}`),
      senderId: message.from_user_id,
      receivedAt: new Date(
        message.create_time_ms ?? this.#clock.now().getTime(),
      ).toISOString(),
      text,
      attachments,
    });
  }

  async #setHealth(health: ChannelHealth): Promise<void> {
    this.#health = health;
    await this.#context?.onHealth(this.id, health);
  }
}

async function sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return;
  }
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(resolve, milliseconds);
    const abort = () => {
      clearTimeout(timeout);
      resolve();
    };
    signal.addEventListener("abort", abort, { once: true });
    timeout.unref?.();
  });
}
