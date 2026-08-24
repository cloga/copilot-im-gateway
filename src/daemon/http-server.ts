import { randomUUID } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { URL } from "node:url";
import { ZodError, type ZodType } from "zod";
import { GatewayError, gatewayErrorCodes, toErrorEnvelope } from "../core/errors.js";
import { constantTimeTokenEqual } from "../core/security.js";
import type { GatewayService } from "./gateway.js";
import {
  allowedSenderSchema,
  adminApprovalDecisionSchema,
  approvalConsumeSchema,
  approvalDecisionSchema,
  approvalRequestSchema,
  bindingSchema,
  completeMessageSchema,
  inboundMessageSchema,
  leaseRequestSchema,
  loginPollSchema,
  outboundMessageSchema,
  workspaceAliasSchema,
} from "./schemas.js";

const maxBodyBytes = 1024 * 1024;

export interface GatewayHttpServerOptions {
  service: GatewayService;
  bearerToken: string;
  port: number;
}

export interface RunningGatewayServer {
  server: Server;
  url: string;
  close(): Promise<void>;
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

export async function startGatewayHttpServer(
  options: GatewayHttpServerOptions,
): Promise<RunningGatewayServer> {
  const server = createServer((request, response) => {
    void handleRequest(options, request, response);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Gateway server did not expose a TCP address.");
  }
  return {
    server,
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) {
            resolve();
          } else {
            reject(error);
          }
        });
      }),
  };
}

async function handleRequest(
  options: GatewayHttpServerOptions,
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

    authenticate(request, options.bearerToken);

    if (method === "GET" && pathname === "/v1/status") {
      sendJson(response, 200, options.service.getStatus());
      return;
    }
    if (method === "GET" && pathname === "/v1/audit") {
      const limit = Math.min(
        500,
        Math.max(1, Number(requestUrl.searchParams.get("limit") ?? 100)),
      );
      sendJson(response, 200, { events: options.service.store.listAudit(limit) });
      return;
    }
    if (method === "POST" && pathname === "/v1/workspace-aliases") {
      const input = await readJson(request, workspaceAliasSchema);
      const now = new Date().toISOString();
      options.service.store.upsertWorkspaceAlias(
        input.alias,
        input.path,
        input.classification,
        now,
      );
      options.service.store.appendAudit({
        createdAt: now,
        eventType: "workspace.alias.updated",
        actor: "local-admin",
        details: { alias: input.alias, classification: input.classification },
      });
      sendJson(response, 200, options.service.store.getWorkspaceAlias(input.alias));
      return;
    }
    if (method === "POST" && pathname === "/v1/allowed-senders") {
      const input = await readJson(request, allowedSenderSchema);
      const now = new Date().toISOString();
      options.service.store.allowSender(
        input.channelId,
        input.senderId,
        input.displayName,
        now,
      );
      options.service.store.appendAudit({
        createdAt: now,
        eventType: "sender.allowed",
        actor: "local-admin",
        details: { channelId: input.channelId, senderId: input.senderId },
      });
      sendJson(response, 201, { ok: true });
      return;
    }
    if (method === "POST" && pathname === "/v1/bindings") {
      const input = await readJson(request, bindingSchema);
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
      options.service.store.appendAudit({
        createdAt: new Date().toISOString(),
        eventType: "session.binding.updated",
        actor: "local-admin",
        routeKey: binding.routeKey,
        details: {
          sessionId: binding.sessionId,
          workspaceAlias: binding.workspaceAlias,
        },
      });
      sendJson(response, 200, binding);
      return;
    }
    if (method === "POST" && pathname === "/v1/inbound") {
      const input = await readJson(request, inboundMessageSchema);
      await options.service.onInbound({
        channelId: input.channelId,
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
      });
      sendJson(response, 202, { accepted: true });
      return;
    }
    const loginStartMatch = /^\/v1\/channels\/([^/]+)\/login\/start$/.exec(
      pathname,
    );
    if (method === "POST" && loginStartMatch !== null) {
      const channelId = decodeURIComponent(loginStartMatch[1] ?? "");
      const snapshot = await options.service.getLoginChannel(channelId).startLogin();
      sendJson(response, 200, snapshot);
      return;
    }
    const loginPollMatch = /^\/v1\/channels\/([^/]+)\/login\/poll$/.exec(
      pathname,
    );
    if (method === "POST" && loginPollMatch !== null) {
      const channelId = decodeURIComponent(loginPollMatch[1] ?? "");
      const input = await readJson(request, loginPollSchema);
      const snapshot = await options.service
        .getLoginChannel(channelId)
        .pollLogin(input.verifyCode);
      sendJson(response, 200, snapshot);
      return;
    }
    if (method === "POST" && pathname === "/v1/messages/lease") {
      const input = await readJson(request, leaseRequestSchema);
      const leased = options.service.leaseInbound(
        input.sessionId,
        input.leaseSeconds,
      );
      sendJson(response, 200, { message: leased ?? null });
      return;
    }
    const completeMatch = /^\/v1\/messages\/(\d+)\/complete$/.exec(pathname);
    if (method === "POST" && completeMatch !== null) {
      const id = Number(completeMatch[1]);
      const input = await readJson(request, completeMessageSchema);
      options.service.store.completeInbound(
        id,
        input.leaseId,
        input.outcome,
        input.errorCode,
      );
      sendJson(response, 200, { ok: true });
      return;
    }
    if (method === "POST" && pathname === "/v1/outbound") {
      const input = await readJson(request, outboundMessageSchema);
      const chunks = await options.service.sendOutbound(input);
      sendJson(response, 202, { accepted: true, chunks });
      return;
    }
    if (method === "POST" && pathname === "/v1/approvals") {
      const input = await readJson(request, approvalRequestSchema);
      const approval = options.service.createApproval(input);
      sendJson(response, 201, approval);
      return;
    }
    if (method === "POST" && pathname === "/v1/approvals/decision") {
      const input = await readJson(request, approvalDecisionSchema);
      const record = options.service.decideApproval(input);
      sendJson(response, 200, record);
      return;
    }
    if (method === "POST" && pathname === "/v1/approvals/admin-decision") {
      const input = await readJson(request, adminApprovalDecisionSchema);
      const now = new Date().toISOString();
      const record = options.service.store.decideApprovalByRequestId({
        ...input,
        now,
      });
      options.service.store.appendAudit({
        createdAt: now,
        eventType: `approval.${input.decision}`,
        actor: "local-admin",
        routeKey: `${record.identity.channelId}:${record.identity.conversationId}`,
        details: { requestId: record.requestId },
      });
      sendJson(response, 200, record);
      return;
    }
    if (method === "POST" && pathname === "/v1/approvals/consume") {
      const input = await readJson(request, approvalConsumeSchema);
      const record = options.service.store.consumeApproval(
        input.requestId,
        input.sessionId,
        new Date().toISOString(),
      );
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
              code: gatewayErrorCodes.conflict,
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
