import { randomUUID } from "node:crypto";
import type {
  ChannelContext,
  ChannelHealth,
  ChannelLoginSnapshot,
  ImOutboundMessage,
  LoginCapableChannelAdapter,
} from "../../core/contracts.js";
import { localTenantId } from "../../core/contracts.js";
import { GatewayError, gatewayErrorCodes } from "../../core/errors.js";
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
  generation: number;
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
  #loginGeneration = 0;
  #loginTransition: Promise<void> = Promise.resolve();
  #stopped = true;

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
    this.#stopped = false;
    this.#loginGeneration += 1;
    this.#context = context;
    this.#credentials = this.#store.getActiveChannelAccount<WeixinCredentials>(
      localTenantId,
      this.id,
    )?.credentials;
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
    this.#stopped = true;
    this.#loginGeneration += 1;
    await this.#serializeLoginTransition(async () => {
      this.#login = undefined;
      await this.#stopPolling();
      await this.#setHealth({ state: "stopped" });
    });
  }

  async startLogin(): Promise<ChannelLoginSnapshot> {
    const generation = ++this.#loginGeneration;
    const localTokens =
      this.#credentials === undefined ? [] : [this.#credentials.botToken];
    const qr = await this.#protocol.getLoginQr(localTokens);
    return this.#serializeLoginTransition(async () => {
      if (generation !== this.#loginGeneration) {
        return { state: "not_started" };
      }
      if (this.#stopped) {
        return { state: "not_started" };
      }
      this.#login = {
        generation,
        qrCode: qr.id,
        qrCodeUrl: qr.url,
        pollingBaseUrl: qr.pollingBaseUrl,
        startedAt: this.#clock.now().getTime(),
      };
      await this.#setHealth({
        state: "awaiting_login",
        since: this.#clock.now().toISOString(),
        qrCodeUrl: qr.url,
      });
      return { state: "waiting", qrCodeUrl: qr.url };
    });
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
    return this.#serializeLoginTransition(async () => {
      if (
        this.#login !== login ||
        login.generation !== this.#loginGeneration
        || this.#stopped
      ) {
        return { state: "not_started" };
      }
      return this.#applyLoginStatus(login, status);
    });
  }

  async #applyLoginStatus(
    login: ActiveLogin,
    status: WeixinLoginStatus,
  ): Promise<ChannelLoginSnapshot> {
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
        const credentials: WeixinCredentials = {
          botToken: status.bot_token,
          botId: status.ilink_bot_id,
          baseUrl: status.baseurl,
          ...(status.ilink_user_id === undefined
            ? {}
            : { userId: status.ilink_user_id }),
        };
        this.#login = undefined;
        await this.#stopPolling();
        if (login.generation !== this.#loginGeneration || this.#stopped) {
          await this.#startPolling();
          return { state: "not_started" };
        }
        this.#credentials = credentials;
        this.#store.setActiveChannelAccount(
          {
            tenantId: localTenantId,
            channelId: this.id,
            accountId: credentials.botId,
          },
          credentials,
          this.#clock.now().toISOString(),
          status.ilink_user_id === undefined
            ? {}
            : { userId: status.ilink_user_id },
        );
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
    if (
      message.tenantId !== localTenantId ||
      message.channelId !== this.id ||
      message.accountId !== this.#credentials.botId ||
      message.senderId !== message.conversationId
    ) {
      throw new Error(
        "Outbound message identity does not match the active Weixin account and conversation owner.",
      );
    }
    const accountIdentity = {
      tenantId: localTenantId,
      channelId: this.id,
      accountId: this.#credentials.botId,
    };
    const contextToken = this.#store.getChannelState<string>(
      accountIdentity,
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
    if (
      this.#stopped ||
      this.#credentials === undefined ||
      this.#pollTask !== undefined
    ) {
      return;
    }

    const credentials = this.#credentials;
    const controller = new AbortController();
    this.#pollController = controller;
    const started = this.#setHealth({
      state: "starting",
      since: this.#clock.now().toISOString(),
    });
    const task = started
      .then(async () => this.#pollLoop(credentials, controller.signal))
      .finally(() => {
        if (this.#pollTask === task) {
          this.#pollTask = undefined;
          this.#pollController = undefined;
        }
      });
    this.#pollTask = task;
    await started;
    await this.#setHealth({
      state: "ready",
      since: this.#clock.now().toISOString(),
      accountLabel: credentials.botId,
    });
  }

  async #stopPolling(): Promise<void> {
    const task = this.#pollTask;
    if (task === undefined) {
      return;
    }

    this.#pollController?.abort();
    await task;
    this.#pollTask = undefined;
    this.#pollController = undefined;
  }

  async #serializeLoginTransition<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.#loginTransition;
    let release: (() => void) | undefined;
    this.#loginTransition = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
    }
  }

  async #pollLoop(
    credentials: WeixinCredentials,
    signal: AbortSignal,
  ): Promise<void> {
    let cursor =
      this.#store.getChannelState<string>(
        {
          tenantId: localTenantId,
          channelId: this.id,
          accountId: credentials.botId,
        },
        "updates-cursor",
      ) ?? "";
    let desiredTimeoutMs = 35_000;
    let retryMs = 2_000;
    while (!signal.aborted) {
      try {
        const updates = await this.#protocol.getUpdates({
          credentials,
          cursor,
          desiredTimeoutMs,
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
        for (const message of updates.messages) {
          await this.#acceptMessage(credentials, message);
        }
        if (updates.cursor.length > 0 && updates.cursor !== cursor) {
          cursor = updates.cursor;
          this.#store.setChannelState(
            {
              tenantId: localTenantId,
              channelId: this.id,
              accountId: credentials.botId,
            },
            "updates-cursor",
            cursor,
            this.#clock.now().toISOString(),
          );
        }
        if (updates.longPollingTimeoutMs > 0) {
          desiredTimeoutMs = updates.longPollingTimeoutMs;
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

  async #acceptMessage(
    credentials: WeixinCredentials,
    message: WeixinMessage,
  ): Promise<void> {
    if (
      message.message_type !== 1 ||
      message.from_user_id === undefined ||
      message.context_token === undefined
    ) {
      return;
    }
    const senderId = message.from_user_id;
    const messageId =
      message.client_id ??
      String(message.message_id ?? `${message.create_time_ms ?? 0}`);
    const receivedAt = new Date(
      message.create_time_ms ?? this.#clock.now().getTime(),
    ).toISOString();
    try {
      await this.#context?.onInbound({
        identity: {
          tenantId: localTenantId,
          channelId: this.id,
          accountId: credentials.botId,
          conversationId: senderId,
          senderId,
        },
        messageId,
        receivedAt,
        materialize: async () => {
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
        this.#store.setChannelState(
          {
            tenantId: localTenantId,
            channelId: this.id,
            accountId: credentials.botId,
          },
          `context:${senderId}`,
          message.context_token,
          this.#clock.now().toISOString(),
        );
        return {
          tenantId: localTenantId,
          channelId: this.id,
          accountId: credentials.botId,
          conversationId: senderId,
          messageId,
          senderId,
          receivedAt,
          text,
          attachments,
        };
        },
      });
    } catch (error) {
      if (
        error instanceof GatewayError &&
        (error.code === gatewayErrorCodes.senderDenied ||
          error.code === gatewayErrorCodes.workspaceDenied ||
          error.code === gatewayErrorCodes.rateLimited ||
          error.code === gatewayErrorCodes.capacityExceeded)
      ) {
        return;
      }
      throw error;
    }
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
