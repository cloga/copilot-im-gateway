import { createHmac, randomUUID } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { URL } from "node:url";
import { ZodError, type ZodType } from "zod";
import {
  canonicalizeIdentityComponents,
  deferInboundMessage,
} from "../core/contracts.js";
import { GatewayError, gatewayErrorCodes, toErrorEnvelope } from "../core/errors.js";
import { constantTimeTokenEqual } from "../core/security.js";
import type { GatewayService } from "./gateway.js";
import {
  legacyV1LoginPollSchema,
  legacyV1WorkspaceAliasSchema,
  v2AllowedSenderSchema,
  v2AdminApprovalDecisionSchema,
  v2ApprovalConsumeSchema,
  v2ApprovalDecisionSchema,
  v2ApprovalRequestSchema,
  v2BindingSchema,
  v2CompleteMessageSchema,
  v2InboundMessageSchema,
  v2LeaseRequestSchema,
  v2LoginPollSchema,
  v2OutboundMessageSchema,
  v2ShutdownIdentityRequestSchema,
  v2ShutdownRequestSchema,
  v2WorkspaceAliasSchema,
} from "./schemas.js";

const maxBodyBytes = 1024 * 1024;
const shutdownChallengeTtlMs = 10_000;
const shutdownChallengeReplayRetentionMs = 5 * 60_000;
const maxShutdownChallenges = 64;
export const gatewayApiVersion = 2;
export const gatewayCapabilities = [
  "account-scoped-routing",
  "sender-bound-routing",
  "operation-bound-approvals",
  "reservation-ownership",
] as const;

export interface GatewayHttpHandlerOptions {
  service: GatewayService;
  bearerToken: string;
  onShutdown?: () => Promise<void> | void;
  shutdownProtocolDependencies?: {
    now?: () => number;
    createId?: () => string;
  };
}

export interface GatewayHttpServerOptions extends GatewayHttpHandlerOptions {
  port: number;
}

export interface RunningGatewayServer {
  server: Server;
  url: string;
  close(): Promise<void>;
}

export interface ReservedGatewayHttpServer extends RunningGatewayServer {
  activate(options: GatewayHttpHandlerOptions): RunningGatewayServer;
}

interface ShutdownOwner {
  pid: number;
  creationMarker: string;
  executablePath: string;
  entrypoint: string;
}

interface ShutdownIdentityRequest {
  protocolVersion: 1;
  owner: ShutdownOwner;
  port: number;
  clientNonce: string;
  requestProof: string;
}

interface ShutdownRequest {
  protocolVersion: 1;
  instanceId: string;
  challengeId: string;
  clientNonce: string;
  responseProof: string;
}

interface ShutdownChallengeRecord {
  instanceId: string;
  challengeId: string;
  clientNonce: string;
  responseProof: string;
  expiresAtMs: number;
  retainedUntilMs: number;
  state: "active" | "consumed" | "expired";
}

function shutdownProof(
  bearerToken: string,
  purpose: "identity-request" | "identity-response",
  values: readonly string[],
): string {
  return createHmac("sha256", bearerToken)
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

class ShutdownChallengeRegistry {
  readonly #bearerToken: string;
  readonly #processId: number;
  readonly #port: number;
  readonly #now: () => number;
  readonly #createId: () => string;
  readonly #instanceId: string;
  readonly #challenges = new Map<string, ShutdownChallengeRecord>();

  constructor(options: {
    bearerToken: string;
    processId: number;
    port: number;
    now: () => number;
    createId: () => string;
  }) {
    this.#bearerToken = options.bearerToken;
    this.#processId = options.processId;
    this.#port = options.port;
    this.#now = options.now;
    this.#createId = options.createId;
    this.#instanceId = this.#createId();
  }

  issue(input: ShutdownIdentityRequest): {
    protocolVersion: 1;
    apiVersion: number;
    capabilities: typeof gatewayCapabilities;
    instanceId: string;
    challengeId: string;
    owner: ShutdownOwner;
    port: number;
    clientNonce: string;
    expiresAt: number;
    responseProof: string;
  } {
    const requestProof = shutdownProof(
      this.#bearerToken,
      "identity-request",
      [
        String(input.owner.pid),
        input.owner.creationMarker,
        String(input.port),
        input.clientNonce,
        input.owner.executablePath,
        input.owner.entrypoint,
      ],
    );
    if (
      input.owner.pid !== this.#processId ||
      input.port !== this.#port ||
      !constantTimeTokenEqual(input.requestProof, requestProof)
    ) {
      throw new GatewayError({
        code: gatewayErrorCodes.authenticationRequired,
        message: "Gateway shutdown identity proof is invalid.",
        status: 401,
      });
    }

    const now = this.#readNow();
    this.#cleanupRetained(now);
    if (
      [...this.#challenges.values()].some(
        (challenge) => challenge.clientNonce === input.clientNonce,
      )
    ) {
      throw new GatewayError({
        code: gatewayErrorCodes.shutdownChallengeReplayed,
        message: "Gateway shutdown identity nonce was already used.",
        status: 409,
      });
    }
    if (this.#challenges.size >= maxShutdownChallenges) {
      throw new GatewayError({
        code: gatewayErrorCodes.shutdownChallengeCapacityExceeded,
        message: "Gateway shutdown challenge capacity is temporarily exhausted.",
        status: 503,
        retryable: true,
      });
    }

    const challengeId = this.#createId();
    if (this.#challenges.has(challengeId)) {
      throw new GatewayError({
        code: gatewayErrorCodes.internal,
        message: "Gateway shutdown challenge generation failed.",
        status: 500,
      });
    }
    const expiresAtMs = now + shutdownChallengeTtlMs;
    const responseProof = shutdownProof(
      this.#bearerToken,
      "identity-response",
      [
        String(gatewayApiVersion),
        this.#instanceId,
        challengeId,
        String(input.owner.pid),
        input.owner.creationMarker,
        String(input.port),
        input.clientNonce,
        String(expiresAtMs),
        input.owner.executablePath,
        input.owner.entrypoint,
      ],
    );
    this.#challenges.set(challengeId, {
      instanceId: this.#instanceId,
      challengeId,
      clientNonce: input.clientNonce,
      responseProof,
      expiresAtMs,
      retainedUntilMs:
        expiresAtMs + shutdownChallengeReplayRetentionMs,
      state: "active",
    });
    return {
      protocolVersion: 1,
      apiVersion: gatewayApiVersion,
      capabilities: gatewayCapabilities,
      instanceId: this.#instanceId,
      challengeId,
      owner: input.owner,
      port: input.port,
      clientNonce: input.clientNonce,
      expiresAt: expiresAtMs,
      responseProof,
    };
  }

  consume(input: ShutdownRequest): void {
    const now = this.#readNow();
    this.#cleanupRetained(now);
    const challenge = this.#challenges.get(input.challengeId);
    if (challenge === undefined) {
      throw new GatewayError({
        code: gatewayErrorCodes.shutdownChallengeInvalid,
        message: "Gateway shutdown challenge is invalid.",
        status: 401,
      });
    }
    if (challenge.state === "consumed") {
      throw new GatewayError({
        code: gatewayErrorCodes.shutdownChallengeReplayed,
        message: "Gateway shutdown challenge was already consumed.",
        status: 409,
      });
    }
    if (challenge.state === "expired" || now >= challenge.expiresAtMs) {
      challenge.state = "expired";
      throw new GatewayError({
        code: gatewayErrorCodes.shutdownChallengeExpired,
        message: "Gateway shutdown challenge expired.",
        status: 409,
      });
    }
    if (
      input.instanceId !== challenge.instanceId ||
      input.clientNonce !== challenge.clientNonce ||
      !constantTimeTokenEqual(input.responseProof, challenge.responseProof)
    ) {
      throw new GatewayError({
        code: gatewayErrorCodes.shutdownChallengeInvalid,
        message: "Gateway shutdown challenge is invalid.",
        status: 401,
      });
    }
    challenge.state = "consumed";
  }

  #readNow(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now)) {
      throw new Error("Shutdown challenge clock returned an invalid timestamp.");
    }
    return now;
  }

  #cleanupRetained(now: number): void {
    for (const [challengeId, challenge] of this.#challenges) {
      if (challenge.retainedUntilMs <= now) {
        this.#challenges.delete(challengeId);
      } else if (
        challenge.state === "active" &&
        challenge.expiresAtMs <= now
      ) {
        challenge.state = "expired";
      }
    }
  }
}

interface ActiveGatewayHttpHandlerOptions {
  service: GatewayService;
  bearerToken: string;
  onShutdown?: () => Promise<void> | void;
  shutdownChallenges: ShutdownChallengeRegistry;
}

function isLoopbackOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      (url.hostname === "127.0.0.1" ||
        url.hostname === "localhost" ||
        url.hostname === "[::1]")
    );
  } catch {
    return false;
  }
}

function setCorsHeaders(
  request: IncomingMessage,
  response: ServerResponse,
): void {
  const origin = request.headers.origin;
  if (origin !== undefined && isLoopbackOrigin(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.setHeader("Vary", "Origin");
  }
}

function sendJson(
  response: ServerResponse,
  status: number,
  payload: unknown,
): void {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  response.end(JSON.stringify(payload));
}

async function readJson<T>(
  request: IncomingMessage,
  schema: ZodType<T>,
): Promise<T> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > maxBodyBytes) {
      throw new GatewayError({
        code: gatewayErrorCodes.invalidInput,
        message: "Request body exceeds the 1 MiB limit.",
        status: 413,
      });
    }
    chunks.push(buffer);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new GatewayError({
      code: gatewayErrorCodes.invalidInput,
      message: "Request body must be valid JSON.",
      status: 400,
    });
  }
  return schema.parse(parsed);
}

function authenticate(
  request: IncomingMessage,
  expectedToken: string,
): void {
  const authorization = request.headers.authorization;
  const actualToken = authorization?.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : undefined;
  if (!constantTimeTokenEqual(actualToken, expectedToken)) {
    throw new GatewayError({
      code: gatewayErrorCodes.authenticationRequired,
      message: "A valid gateway bearer token is required.",
      status: 401,
    });
  }
}

function isUnsafeLegacyV1Operation(method: string, pathname: string): boolean {
  if (method !== "POST") {
    return false;
  }
  return (
    pathname === "/v1/allowed-senders" ||
    pathname === "/v1/bindings" ||
    pathname === "/v1/inbound" ||
    pathname === "/v1/messages/lease" ||
    /^\/v1\/messages\/\d+\/complete$/.test(pathname) ||
    pathname === "/v1/outbound" ||
    pathname === "/v1/approvals" ||
    pathname === "/v1/approvals/decision" ||
    pathname === "/v1/approvals/admin-decision" ||
    pathname === "/v1/approvals/consume"
  );
}

export async function reserveGatewayHttpServer(
  port: number,
): Promise<ReservedGatewayHttpServer> {
  let handlerOptions: ActiveGatewayHttpHandlerOptions | undefined;
  let activated = false;
  let closed = false;
  const server = createServer((request, response) => {
    const options = handlerOptions;
    if (options === undefined) {
      const requestId = randomUUID();
      response.setHeader("X-Request-Id", requestId);
      setCorsHeaders(request, response);
      sendJson(
        response,
        503,
        toErrorEnvelope(
          new GatewayError({
            code: gatewayErrorCodes.internal,
            message: "The gateway is still starting.",
            status: 503,
            retryable: true,
          }),
          requestId,
        ),
      );
      return;
    }
    void handleRequest(options, request, response);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Gateway server did not expose a TCP address.");
  }
  const close = async (): Promise<void> => {
    if (closed) {
      return;
    }
    closed = true;
    if (!server.listening) {
      return;
    }
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error === undefined) {
          resolve();
        } else {
          reject(error);
        }
      });
    });
  };
  const running: RunningGatewayServer = {
    server,
    url: `http://127.0.0.1:${address.port}`,
    close,
  };
  return {
    ...running,
    activate(options): RunningGatewayServer {
      if (closed) {
        throw new Error("Gateway HTTP reservation is already closed.");
      }
      if (activated) {
        throw new Error("Gateway HTTP reservation is already active.");
      }
      const onShutdown = options.onShutdown;
      let shutdownScheduled = false;
      const shutdownProtocolDependencies =
        options.shutdownProtocolDependencies ?? {};
      handlerOptions = {
        service: options.service,
        bearerToken: options.bearerToken,
        shutdownChallenges: new ShutdownChallengeRegistry({
          bearerToken: options.bearerToken,
          processId: process.pid,
          port: address.port,
          now: shutdownProtocolDependencies.now ?? Date.now,
          createId: shutdownProtocolDependencies.createId ?? randomUUID,
        }),
        ...(onShutdown === undefined
          ? {}
          : {
              onShutdown: () => {
                if (shutdownScheduled) {
                  return;
                }
                shutdownScheduled = true;
                setImmediate(() => {
                  void Promise.resolve()
                    .then(onShutdown)
                    .catch((error: unknown) => {
                      console.error("Gateway shutdown callback failed.", error);
                    });
                });
              },
            }),
      };
      activated = true;
      return running;
    },
  };
}

export async function startGatewayHttpServer(
  options: GatewayHttpServerOptions,
): Promise<RunningGatewayServer> {
  const reservation = await reserveGatewayHttpServer(options.port);
  try {
    return reservation.activate(options);
  } catch (error) {
    await reservation.close();
    throw error;
  }
}

async function handleRequest(
  options: ActiveGatewayHttpHandlerOptions,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const requestId = randomUUID();
  response.setHeader("X-Request-Id", requestId);
  setCorsHeaders(request, response);

  try {
    const method = request.method ?? "GET";
    const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
    const pathname = requestUrl.pathname;

    if (method === "OPTIONS") {
      const origin = request.headers.origin;
      if (origin === undefined || !isLoopbackOrigin(origin)) {
        throw new GatewayError({
          code: gatewayErrorCodes.authenticationRequired,
          message: "Cross-origin request must originate from loopback.",
          status: 403,
        });
      }
      response.statusCode = 204;
      response.end();
      return;
    }

    if (method === "GET" && pathname === "/healthz") {
      sendJson(response, 200, { status: "ready" });
      return;
    }

    if (method === "POST" && pathname === "/v2/admin/identity") {
      const input = await readJson(request, v2ShutdownIdentityRequestSchema);
      sendJson(response, 200, options.shutdownChallenges.issue(input));
      return;
    }

    authenticate(request, options.bearerToken);

    if (method === "POST" && pathname === "/v2/admin/shutdown") {
      if (options.onShutdown === undefined) {
        throw new GatewayError({
          code: gatewayErrorCodes.internal,
          message: "Gateway shutdown is not available.",
          status: 503,
        });
      }
      const input = await readJson(request, v2ShutdownRequestSchema);
      options.shutdownChallenges.consume(input);
      sendJson(response, 202, { accepted: true });
      void options.onShutdown();
      return;
    }
    if (method === "GET" && pathname === "/v1/status") {
      sendJson(response, 200, options.service.getStatus());
      return;
    }
    if (method === "GET" && pathname === "/v2/status") {
      sendJson(response, 200, {
        apiVersion: gatewayApiVersion,
        capabilities: gatewayCapabilities,
        ...options.service.getStatus(),
      });
      return;
    }
    if (
      method === "GET" &&
      (pathname === "/v1/audit" || pathname === "/v2/audit")
    ) {
      const limit = Math.min(
        500,
        Math.max(1, Number(requestUrl.searchParams.get("limit") ?? 100)),
      );
      sendJson(response, 200, { events: options.service.store.listAudit(limit) });
      return;
    }
    if (
      method === "POST" &&
      (pathname === "/v1/workspace-aliases" ||
        pathname === "/v2/workspace-aliases")
    ) {
      const input = await readJson(
        request,
        pathname.startsWith("/v1/")
          ? legacyV1WorkspaceAliasSchema
          : v2WorkspaceAliasSchema,
      );
      const now = new Date().toISOString();
      options.service.store.upsertWorkspaceAlias(
        input.alias,
        input.path,
        input.classification,
        now,
      );
      sendJson(response, 200, options.service.store.getWorkspaceAlias(input.alias));
      return;
    }
    const loginStartMatch =
      /^\/v1\/channels\/([^/]+)\/login\/start$/.exec(pathname) ??
      /^\/v2\/channels\/([^/]+)\/login\/start$/.exec(pathname);
    if (method === "POST" && loginStartMatch !== null) {
      const channelId = decodeURIComponent(loginStartMatch[1] ?? "");
      const snapshot = await options.service.getLoginChannel(channelId).startLogin();
      sendJson(response, 200, snapshot);
      return;
    }
    const loginPollMatch =
      /^\/v1\/channels\/([^/]+)\/login\/poll$/.exec(pathname) ??
      /^\/v2\/channels\/([^/]+)\/login\/poll$/.exec(pathname);
    if (method === "POST" && loginPollMatch !== null) {
      const channelId = decodeURIComponent(loginPollMatch[1] ?? "");
      const input = await readJson(
        request,
        pathname.startsWith("/v1/")
          ? legacyV1LoginPollSchema
          : v2LoginPollSchema,
      );
      const snapshot = await options.service
        .getLoginChannel(channelId)
        .pollLogin(input.verifyCode);
      sendJson(response, 200, snapshot);
      return;
    }

    if (isUnsafeLegacyV1Operation(method, pathname)) {
      throw new GatewayError({
        code: gatewayErrorCodes.upgradeRequired,
        message:
          "This operation requires the account-scoped v2 gateway extension.",
        status: 426,
      });
    }

    if (method === "POST" && pathname === "/v2/allowed-senders") {
      const input = await readJson(request, v2AllowedSenderSchema);
      const now = new Date().toISOString();
      options.service.store.allowSender(
        {
          tenantId: input.tenantId,
          channelId: input.channelId,
          accountId: input.accountId,
          senderId: input.senderId,
        },
        input.displayName,
        now,
      );
      sendJson(response, 201, { ok: true });
      return;
    }
    if (method === "POST" && pathname === "/v2/bindings") {
      const input = await readJson(request, v2BindingSchema);
      const workspace = options.service.store.getWorkspaceAlias(
        input.workspaceAlias,
      );
      if (workspace === undefined || workspace.classification !== "personal") {
        throw new GatewayError({
          code: gatewayErrorCodes.workspaceDenied,
          message:
            "Workspace alias must exist and be classified as personal before binding.",
          status: 403,
        });
      }
      const binding = options.service.store.upsertBinding(
        input,
        new Date().toISOString(),
      );
      sendJson(response, 200, binding);
      return;
    }
    if (method === "POST" && pathname === "/v2/inbound") {
      const input = await readJson(request, v2InboundMessageSchema);
      await options.service.onInbound(deferInboundMessage({
        tenantId: input.tenantId,
        channelId: input.channelId,
        accountId: input.accountId,
        conversationId: input.conversationId,
        messageId: input.messageId,
        senderId: input.senderId,
        receivedAt: input.receivedAt,
        text: input.text,
        attachments: input.attachments.map((attachment) => ({
          id: attachment.id,
          mediaType: attachment.mediaType,
          ...(attachment.sizeBytes === undefined
            ? {}
            : { sizeBytes: attachment.sizeBytes }),
          ...(attachment.fileName === undefined
            ? {}
            : { fileName: attachment.fileName }),
        })),
        ...(input.replyToMessageId === undefined
          ? {}
          : { replyToMessageId: input.replyToMessageId }),
      }));
      sendJson(response, 202, { accepted: true });
      return;
    }
    if (method === "POST" && pathname === "/v2/messages/lease") {
      const input = await readJson(request, v2LeaseRequestSchema);
      const leased = options.service.leaseInbound(
        input.sessionId,
        input.leaseSeconds,
      );
      sendJson(response, 200, { message: leased ?? null });
      return;
    }
    const completeMatch = /^\/v2\/messages\/(\d+)\/complete$/.exec(pathname);
    if (method === "POST" && completeMatch !== null) {
      const id = Number(completeMatch[1]);
      const input = await readJson(request, v2CompleteMessageSchema);
      options.service.completeInbound({
        id,
        leaseId: input.leaseId,
        outcome: input.outcome,
        ...(input.errorCode === undefined ? {} : { errorCode: input.errorCode }),
        retryable: input.retryable,
      });
      sendJson(response, 200, { ok: true });
      return;
    }
    if (method === "POST" && pathname === "/v2/outbound") {
      const input = await readJson(request, v2OutboundMessageSchema);
      const chunks = await options.service.sendOutbound(input);
      sendJson(response, 202, { accepted: true, chunks });
      return;
    }
    if (method === "POST" && pathname === "/v2/approvals") {
      const input = await readJson(request, v2ApprovalRequestSchema);
      const approval = options.service.createApproval(input);
      sendJson(response, 201, approval);
      return;
    }
    if (method === "POST" && pathname === "/v2/approvals/decision") {
      const input = await readJson(request, v2ApprovalDecisionSchema);
      const record = options.service.decideApproval(input);
      sendJson(response, 200, record);
      return;
    }
    if (method === "POST" && pathname === "/v2/approvals/admin-decision") {
      const input = await readJson(request, v2AdminApprovalDecisionSchema);
      const now = new Date().toISOString();
      const record = options.service.store.decideApprovalByRequestId({
        ...input,
        now,
      });
      sendJson(response, 200, record);
      return;
    }
    if (method === "POST" && pathname === "/v2/approvals/consume") {
      const input = await readJson(request, v2ApprovalConsumeSchema);
      const record = options.service.store.consumeApproval({
        ...input,
        now: new Date().toISOString(),
      });
      sendJson(response, 200, { approval: record ?? null });
      return;
    }

    throw new GatewayError({
      code: gatewayErrorCodes.notFound,
      message: "Endpoint not found.",
      status: 404,
    });
  } catch (error) {
    const gatewayError =
      error instanceof GatewayError
        ? error
        : error instanceof ZodError
          ? new GatewayError({
              code: gatewayErrorCodes.invalidInput,
              message: "Request validation failed.",
              status: 400,
              details: {
                issues: error.issues.map((issue) => ({
                  code: issue.code,
                  path: issue.path.join("."),
                  message: issue.message,
                })),
              },
            })
          : new GatewayError({
              code: gatewayErrorCodes.internal,
              message: "The gateway could not complete the request.",
              status: 500,
              retryable: true,
            });
    if (!(error instanceof GatewayError) && !(error instanceof ZodError)) {
      console.error(`[${requestId}] Unhandled gateway request error`, error);
    }
    sendJson(
      response,
      gatewayError.status,
      toErrorEnvelope(gatewayError, requestId),
    );
  }
}
