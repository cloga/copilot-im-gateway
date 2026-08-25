import { createHmac, randomUUID } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { URL } from "node:url";
import { ZodError, type ZodType } from "zod";
import { deferInboundMessage } from "../core/contracts.js";
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
  v2WorkspaceAliasSchema,
} from "./schemas.js";

const maxBodyBytes = 1024 * 1024;
const shutdownChallengePattern = /^[0-9a-f]{64}$/u;
const shutdownProofPattern = /^[0-9a-f]{64}$/u;
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

function shutdownProof(
  bearerToken: string,
  purpose: "request" | "response",
  challenge: string,
): string {
  return createHmac("sha256", bearerToken)
    .update(`${purpose}\0${challenge}`, "utf8")
    .digest("hex");
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

async function requireEmptyBody(request: IncomingMessage): Promise<void> {
  let size = 0;
  for await (const chunk of request) {
    size += Buffer.isBuffer(chunk)
      ? chunk.length
      : Buffer.byteLength(chunk);
    if (size > maxBodyBytes) {
      throw new GatewayError({
        code: gatewayErrorCodes.invalidInput,
        message: "Request body exceeds the 1 MiB limit.",
        status: 413,
      });
    }
  }
  if (size !== 0) {
    throw new GatewayError({
      code: gatewayErrorCodes.invalidInput,
      message: "This endpoint does not accept a request body.",
      status: 400,
    });
  }
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
  let handlerOptions: GatewayHttpHandlerOptions | undefined;
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
      handlerOptions = {
        service: options.service,
        bearerToken: options.bearerToken,
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
  options: GatewayHttpHandlerOptions,
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

    if (method === "GET" && pathname === "/v2/admin/identity") {
      const challenge = request.headers["x-gateway-shutdown-challenge"];
      const proof = request.headers["x-gateway-shutdown-proof"];
      if (
        typeof challenge !== "string" ||
        typeof proof !== "string" ||
        !shutdownChallengePattern.test(challenge) ||
        !shutdownProofPattern.test(proof) ||
        !constantTimeTokenEqual(
          proof,
          shutdownProof(options.bearerToken, "request", challenge),
        )
      ) {
        throw new GatewayError({
          code: gatewayErrorCodes.authenticationRequired,
          message: "Gateway shutdown identity proof is invalid.",
          status: 401,
        });
      }
      sendJson(response, 200, {
        apiVersion: gatewayApiVersion,
        capabilities: gatewayCapabilities,
        proof: shutdownProof(options.bearerToken, "response", challenge),
      });
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
      await requireEmptyBody(request);
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
