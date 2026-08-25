import { randomBytes } from "node:crypto";
import { z } from "zod";
import { isWellFormedUnicode } from "../../core/contracts.js";

const protocolString = z
  .string()
  .refine(isWellFormedUnicode, "Protocol string must be well-formed Unicode.");
const protocolIdentifier = z
  .string()
  .refine(isWellFormedUnicode, "Identifier must be well-formed Unicode.");
const protocolHeaderValue = z
  .string()
  .min(1)
  .refine(isWellFormedUnicode, "Header value must be well-formed Unicode.")
  .refine(
    (value) =>
      !Array.from(value).some((character) => {
        const codePoint = character.codePointAt(0);
        return (
          codePoint !== undefined && (codePoint <= 0x1f || codePoint === 0x7f)
        );
      }),
    "Header value must not contain control characters.",
  );
const protocolUrl = protocolString.pipe(z.string().url());
const protocolToken = protocolString;

const qrCodeResponseSchema = z.object({
  qrcode: protocolString.pipe(z.string().min(1)),
  qrcode_img_content: protocolUrl,
});

const loginStatusSchema = z.object({
  status: z.enum([
    "wait",
    "scaned",
    "confirmed",
    "expired",
    "scaned_but_redirect",
    "need_verifycode",
    "verify_code_blocked",
    "binded_redirect",
  ]),
  bot_token: protocolHeaderValue.optional(),
  ilink_bot_id: protocolIdentifier.optional(),
  baseurl: protocolUrl.optional(),
  ilink_user_id: protocolIdentifier.optional(),
  redirect_host: protocolString.optional(),
});

const messageItemSchema = z.object({
  type: z.number().int().optional(),
  msg_id: protocolIdentifier.optional(),
  text_item: z.object({ text: z.string().optional() }).optional(),
  voice_item: z.object({ text: z.string().optional() }).optional(),
  image_item: z
    .object({
      mid_size: z.number().int().nonnegative().optional(),
    })
    .passthrough()
    .optional(),
  file_item: z
    .object({
      file_name: z.string().optional(),
      len: z.string().optional(),
    })
    .passthrough()
    .optional(),
  video_item: z
    .object({
      video_size: z.number().int().nonnegative().optional(),
    })
    .passthrough()
    .optional(),
});

const weixinMessageSchema = z.object({
  message_id: z.number().optional(),
  from_user_id: protocolIdentifier.optional(),
  to_user_id: protocolIdentifier.optional(),
  client_id: protocolIdentifier.optional(),
  create_time_ms: z.number().optional(),
  message_type: z.number().optional(),
  item_list: z.array(messageItemSchema).optional(),
  context_token: protocolToken.optional(),
  run_id: protocolIdentifier.optional(),
});

const updatesResponseSchema = z.object({
  ret: z.number().optional(),
  errcode: z.number().optional(),
  errmsg: z.string().optional(),
  msgs: z.array(weixinMessageSchema).optional(),
  get_updates_buf: protocolToken.optional(),
  longpolling_timeout_ms: z.number().int().optional(),
});

const sendResponseSchema = z.object({
  ret: z.number().optional(),
  errmsg: z.string().optional(),
});

export type WeixinLoginStatus = z.infer<typeof loginStatusSchema>;
export type WeixinMessage = z.infer<typeof weixinMessageSchema>;

export interface WeixinCredentials {
  botToken: string;
  botId: string;
  baseUrl: string;
  userId?: string;
}

const credentialsSchema = z.object({
  botToken: protocolHeaderValue,
  botId: protocolIdentifier,
  baseUrl: protocolUrl,
  userId: protocolIdentifier.optional(),
});

const loginPollInputSchema = z.object({
  baseUrl: protocolUrl,
  qrCode: protocolToken,
  verifyCode: protocolToken.optional(),
});

export interface WeixinUpdates {
  messages: WeixinMessage[];
  cursor: string;
  longPollingTimeoutMs: number;
  errorCode?: number;
  errorMessage?: string;
}

export interface WeixinProtocolClient {
  getLoginQr(
    localTokens: string[],
  ): Promise<{ id: string; url: string; pollingBaseUrl: string }>;
  pollLoginStatus(input: {
    baseUrl: string;
    qrCode: string;
    verifyCode?: string;
  }): Promise<WeixinLoginStatus>;
  getUpdates(input: {
    credentials: WeixinCredentials;
    cursor: string;
    desiredTimeoutMs?: number;
    signal: AbortSignal;
  }): Promise<WeixinUpdates>;
  sendText(input: {
    credentials: WeixinCredentials;
    toUserId: string;
    contextToken: string;
    text: string;
    clientId: string;
  }): Promise<void>;
}

export interface FetchWeixinProtocolClientOptions {
  loginBaseUrl?: string;
  appId?: string;
  channelVersion?: string;
  clientVersion?: number;
  fetch?: typeof globalThis.fetch;
}

export class FetchWeixinProtocolClient implements WeixinProtocolClient {
  readonly #loginBaseUrl: string;
  readonly #appId: string;
  readonly #channelVersion: string;
  readonly #clientVersion: number;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: FetchWeixinProtocolClientOptions = {}) {
    this.#loginBaseUrl = protocolUrl.parse(
      options.loginBaseUrl ?? "https://ilinkai.weixin.qq.com",
    );
    this.#appId = protocolHeaderValue.parse(options.appId ?? "bot");
    this.#channelVersion = protocolHeaderValue.parse(
      options.channelVersion ?? "0.1.0",
    );
    this.#clientVersion = options.clientVersion ?? 256;
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  async getLoginQr(
    localTokens: string[],
  ): Promise<{ id: string; url: string; pollingBaseUrl: string }> {
    const validatedLocalTokens = z.array(protocolToken).parse(localTokens);
    const response = await this.#request(
      this.#loginBaseUrl,
      "/ilink/bot/get_bot_qrcode?bot_type=3",
      {
        method: "POST",
        body: { local_token_list: validatedLocalTokens.slice(-10) },
        timeoutMs: 15_000,
      },
    );
    const parsed = qrCodeResponseSchema.parse(response);
    return {
      id: parsed.qrcode,
      url: parsed.qrcode_img_content,
      pollingBaseUrl: this.#loginBaseUrl,
    };
  }

  async pollLoginStatus(input: {
    baseUrl: string;
    qrCode: string;
    verifyCode?: string;
  }): Promise<WeixinLoginStatus> {
    const validated = loginPollInputSchema.parse(input);
    const query = new URLSearchParams({ qrcode: validated.qrCode });
    if (validated.verifyCode !== undefined) {
      query.set("verify_code", validated.verifyCode);
    }
    try {
      const response = await this.#request(
        validated.baseUrl,
        `/ilink/bot/get_qrcode_status?${query.toString()}`,
        { method: "GET", timeoutMs: 35_000 },
      );
      return loginStatusSchema.parse(response);
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        return { status: "wait" };
      }
      throw error;
    }
  }

  async getUpdates(input: {
    credentials: WeixinCredentials;
    cursor: string;
    desiredTimeoutMs?: number;
    signal: AbortSignal;
  }): Promise<WeixinUpdates> {
    const credentials = credentialsSchema.parse(input.credentials);
    const cursor = protocolToken.parse(input.cursor);
    let response: unknown;
    try {
      response = await this.#request(
        credentials.baseUrl,
        "/ilink/bot/getupdates",
        {
          method: "POST",
          body: {
            get_updates_buf: cursor,
            base_info: this.#baseInfo(),
          },
          token: credentials.botToken,
          timeoutMs: Math.max(1_000, (input.desiredTimeoutMs ?? 35_000) + 5_000),
          signal: input.signal,
        },
      );
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        return {
          messages: [],
          cursor,
          longPollingTimeoutMs: input.desiredTimeoutMs ?? 35_000,
        };
      }
      throw error;
    }
    const parsed = updatesResponseSchema.parse(response);
    return {
      messages: parsed.msgs ?? [],
      cursor:
        parsed.get_updates_buf !== undefined &&
        parsed.get_updates_buf.length > 0
          ? parsed.get_updates_buf
          : cursor,
      longPollingTimeoutMs:
        parsed.longpolling_timeout_ms !== undefined &&
        parsed.longpolling_timeout_ms > 0
          ? parsed.longpolling_timeout_ms
          : (input.desiredTimeoutMs ?? 35_000),
      ...(parsed.errcode === undefined ? {} : { errorCode: parsed.errcode }),
      ...(parsed.errmsg === undefined ? {} : { errorMessage: parsed.errmsg }),
    };
  }

  async sendText(input: {
    credentials: WeixinCredentials;
    toUserId: string;
    contextToken: string;
    text: string;
    clientId: string;
  }): Promise<void> {
    const credentials = credentialsSchema.parse(input.credentials);
    const toUserId = protocolIdentifier.parse(input.toUserId);
    const contextToken = protocolToken.parse(input.contextToken);
    const clientId = protocolIdentifier.parse(input.clientId);
    const response = await this.#request(
      credentials.baseUrl,
      "/ilink/bot/sendmessage",
      {
        method: "POST",
        token: credentials.botToken,
        timeoutMs: 15_000,
        body: {
          msg: {
            from_user_id: "",
            to_user_id: toUserId,
            client_id: clientId,
            message_type: 2,
            message_state: 2,
            item_list: [
              {
                type: 1,
                text_item: { text: input.text },
              },
            ],
            context_token: contextToken,
          },
          base_info: this.#baseInfo(),
        },
      },
    );
    const parsed = sendResponseSchema.parse(response);
    if (parsed.ret !== undefined && parsed.ret !== 0) {
      throw new Error(
        `Weixin send failed with ret=${parsed.ret}: ${parsed.errmsg ?? "unknown"}`,
      );
    }
  }

  #baseInfo(): { channel_version: string; bot_agent: string } {
    return {
      channel_version: this.#channelVersion,
      bot_agent: "Copilot-IM-Gateway/0.1.0",
    };
  }

  async #request(
    baseUrl: string,
    endpoint: string,
    options: {
      method: "GET" | "POST";
      body?: unknown;
      token?: string;
      timeoutMs: number;
      signal?: AbortSignal;
    },
  ): Promise<unknown> {
    const validatedBaseUrl = protocolUrl.parse(baseUrl);
    const token =
      options.token === undefined
        ? undefined
        : protocolHeaderValue.parse(options.token);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
    const abort = () => controller.abort();
    options.signal?.addEventListener("abort", abort, { once: true });
    try {
      const response = await this.#fetch(
        new URL(
          endpoint,
          validatedBaseUrl.endsWith("/")
            ? validatedBaseUrl
            : `${validatedBaseUrl}/`,
        ),
        {
          method: options.method,
          headers: {
            "iLink-App-Id": this.#appId,
            "iLink-App-ClientVersion": String(this.#clientVersion),
            ...(options.method === "POST"
              ? {
                  "Content-Type": "application/json",
                  AuthorizationType: "ilink_bot_token",
                  "X-WECHAT-UIN": Buffer.from(
                    String(randomBytes(4).readUInt32BE()),
                  ).toString("base64"),
                }
              : {}),
            ...(token === undefined
              ? {}
              : { Authorization: token }),
          },
          ...(options.body === undefined
            ? {}
            : { body: JSON.stringify(options.body) }),
          signal: controller.signal,
        },
      );
      const text = await response.text();
      if (!response.ok) {
        throw new Error(
          `Weixin API ${endpoint} returned HTTP ${response.status}.`,
        );
      }
      return JSON.parse(text) as unknown;
    } finally {
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", abort);
    }
  }
}
