import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { CopilotSession, PermissionRequest } from "@github/copilot-sdk";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createAdminCanvas,
  setAutoFilledValue,
} from "../.github/extensions/im-gateway/canvas.mjs";
import {
  createPermissionHandler,
  delay,
  displayPath,
  processInboundTurn,
  redactInline,
  runInboundLoop,
  safeHost,
  samePath,
  summarizePermission,
} from "../.github/extensions/im-gateway/extension-runtime.mjs";
import {
  GatewayClient,
  requiredGatewayCapabilities,
  resolveGatewayConnection,
} from "../.github/extensions/im-gateway/gateway-client.mjs";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { force: true, recursive: true }),
    ),
  );
});

describe("Copilot extension security posture", () => {
  it("uses the official extension runtime and never approveAll", async () => {
    const extensionPath = path.join(
      process.cwd(),
      ".github",
      "extensions",
      "im-gateway",
      "extension.mjs",
    );
    const extension = await readFile(extensionPath, "utf8");
    expect(extension).toContain("joinSession");
    expect(extension).toContain("onPermissionRequest");
    expect(extension).not.toContain("approveAll");
    expect(extension).not.toContain("assistant.reasoning");
  });

  it("executes gateway client authentication and stable errors", async () => {
    const directory = await createTemporaryDirectory("gateway-client-");
    const tokenPath = path.join(directory, "auth-token");
    await writeFile(tokenPath, "a".repeat(40), "utf8");
    vi.stubEnv("COPILOT_IM_GATEWAY_DATA_DIR", directory);
    vi.stubEnv("COPILOT_IM_GATEWAY_URL", "http://127.0.0.1:43210/");

    expect(resolveGatewayConnection()).toEqual({
      baseUrl: "http://127.0.0.1:43210/",
      tokenPath,
    });
    const compatibility = {
      apiVersion: 2,
      capabilities: requiredGatewayCapabilities,
      healthy: true,
    };
    const fetchMock = vi.fn(async (input: string | URL | Request) =>
      new Response(
        JSON.stringify(
          String(input).endsWith("/v2/status")
            ? compatibility
            : { accepted: true },
        ),
        {
        headers: { "Content-Type": "application/json" },
        },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const client = new GatewayClient(resolveGatewayConnection());
    await expect(client.status()).resolves.toEqual(compatibility);
    await client.lease("session");
    await client.complete(1, "lease", "failed", "SAFE_ERROR");
    await client.sendOutbound({
      tenantId: "local",
      channelId: "weixin-main",
      accountId: "bot",
      conversationId: "conversation",
      senderId: "sender",
      correlationId: "message",
      text: "safe",
    });
    await client.createApproval({ requestId: "request" });
    await client.consumeApproval(
      "request",
      {
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot",
        conversationId: "conversation",
        senderId: "sender",
        sessionId: "session",
      },
      "a".repeat(64),
    );
    expect(fetchMock).toHaveBeenCalledTimes(11);
    expect(
      fetchMock.mock.calls.map(([input]) => new URL(String(input)).pathname),
    ).toEqual([
      "/v2/status",
      "/v2/status",
      "/v2/messages/lease",
      "/v2/status",
      "/v2/messages/1/complete",
      "/v2/status",
      "/v2/outbound",
      "/v2/status",
      "/v2/approvals",
      "/v2/status",
      "/v2/approvals/consume",
    ]);

    await writeFile(tokenPath, "short", "utf8");
    await expect(client.audit()).rejects.toThrow("token file");
    await writeFile(tokenPath, "a".repeat(40), "utf8");
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: { code: "SAFE_CODE" } }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }),
    );
    await expect(client.audit()).rejects.toThrow("SAFE_CODE");
  });

  it("fails the v2 handshake before unsafe calls against an old daemon", async () => {
    const directory = await createTemporaryDirectory("gateway-old-daemon-");
    const tokenPath = path.join(directory, "auth-token");
    await writeFile(tokenPath, "a".repeat(40), "utf8");
    const fetchMock = vi.fn<typeof fetch>(async () =>
      new Response(JSON.stringify({ error: { code: "NOT_FOUND" } }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const client = new GatewayClient({
      baseUrl: "http://127.0.0.1:32147",
      tokenPath,
    });

    await expect(client.lease("session")).rejects.toMatchObject({
      code: "DAEMON_UPGRADE_REQUIRED",
      status: 426,
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBeUndefined();
  });

  it("reports incomplete daemon capabilities on the same handshake", async () => {
    const directory = await createTemporaryDirectory(
      "gateway-incomplete-daemon-",
    );
    const tokenPath = path.join(directory, "auth-token");
    await writeFile(tokenPath, "a".repeat(40), "utf8");
    const fetchMock = vi.fn<typeof fetch>(async () =>
      new Response(
        JSON.stringify({
          apiVersion: 2,
          capabilities: ["account-scoped-routing"],
        }),
        { headers: { "Content-Type": "application/json" } },
      )
    );
    vi.stubGlobal("fetch", fetchMock);
    const client = new GatewayClient({
      baseUrl: "http://127.0.0.1:32147",
      tokenPath,
    });

    await expect(client.status()).rejects.toMatchObject({
      code: "DAEMON_UPGRADE_REQUIRED",
      status: 426,
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("rechecks compatibility before leasing after daemon replacement", async () => {
    const directory = await createTemporaryDirectory(
      "gateway-replaced-daemon-",
    );
    const tokenPath = path.join(directory, "auth-token");
    await writeFile(tokenPath, "a".repeat(40), "utf8");
    let replaced = false;
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const pathname = new URL(String(input)).pathname;
      if (pathname === "/v2/status" && !replaced) {
        return new Response(
          JSON.stringify({
            apiVersion: 2,
            capabilities: requiredGatewayCapabilities,
          }),
          { headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(JSON.stringify({ error: { code: "NOT_FOUND" } }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new GatewayClient({
      baseUrl: "http://127.0.0.1:32147",
      tokenPath,
    });

    await expect(client.status()).resolves.toMatchObject({ apiVersion: 2 });
    replaced = true;
    await expect(client.lease("session")).rejects.toMatchObject({
      code: "DAEMON_UPGRADE_REQUIRED",
      status: 426,
    });
    expect(
      fetchMock.mock.calls.map(([input]) => new URL(String(input)).pathname),
    ).toEqual(["/v2/status", "/v2/status"]);
  });

  it("updates only Canvas-managed login identity values", () => {
    const input: {
      value: string;
      dataset: Record<string, string | undefined>;
    } = { value: "", dataset: {} };
    setAutoFilledValue(input, "account-a");
    expect(input).toEqual({
      value: "account-a",
      dataset: { autoFilled: "account-a" },
    });
    setAutoFilledValue(input, "account-b");
    expect(input).toEqual({
      value: "account-b",
      dataset: { autoFilled: "account-b" },
    });
    input.value = "user-edited";
    setAutoFilledValue(input, "account-c");
    expect(input).toEqual({ value: "user-edited", dataset: {} });
  });

  it("executes one-time approval state transitions", async () => {
    const directory = await createTemporaryDirectory("permission-runtime-");
    const tokenPath = path.join(directory, "auth-token");
    await writeFile(tokenPath, "a".repeat(40), "utf8");
    const client = new GatewayClient({
      baseUrl: "http://127.0.0.1:32147",
      tokenPath,
    });
    vi.spyOn(client, "createApproval").mockResolvedValue({
      nonce: "nonce",
      expiresAt: "soon",
      operationDigest: "a".repeat(64),
    });
    vi.spyOn(client, "sendOutbound").mockResolvedValue({});
    vi.spyOn(client, "consumeApproval").mockResolvedValue({
      approval: { status: "approved" },
    });
    const controller = new AbortController();
    const turn = {
      tenantId: "local",
      channelId: "weixin-main",
      accountId: "bot",
      conversationId: "conversation",
      senderId: "sender",
      sessionId: "session",
      workspaceAlias: "personal",
      workspaceRoot: process.cwd(),
    };
    const handler = createPermissionHandler({
      client,
      getActiveTurn: () => turn,
      signal: controller.signal,
      randomId: () => "generated-id",
      wait: async () => undefined,
    });

    await expect(
      handler(
        {
          kind: "url",
          url: "https://example.test/path",
          intention: "read docs",
        } as unknown as PermissionRequest,
        { sessionId: "session" },
      ),
    ).resolves.toEqual({
      kind: "approve-once",
      approvedInteractively: true,
    });
    expect(client.createApproval).toHaveBeenCalledWith(
      expect.objectContaining({ requestId: "generated-id", ttlSeconds: 300 }),
    );

    vi.spyOn(client, "consumeApproval").mockResolvedValueOnce({
      approval: { status: "denied" },
    });
    await expect(
      handler(
        {
          kind: "read",
          path: path.join(process.cwd(), "README.md"),
          intention: "inspect",
        } as unknown as PermissionRequest,
        { sessionId: "session" },
      ),
    ).resolves.toMatchObject({ kind: "reject" });

    const noTurnHandler = createPermissionHandler({
      client,
      getActiveTurn: () => undefined,
      signal: controller.signal,
    });
    await expect(
      noTurnHandler(
        { kind: "url" } as unknown as PermissionRequest,
        { sessionId: "other" },
      ),
    ).resolves.toEqual({ kind: "no-result" });
    await expect(
      handler(
        {
          kind: "url",
          managedApprovalRequired: true,
        } as unknown as PermissionRequest,
        { sessionId: "session" },
      ),
    ).resolves.toMatchObject({ kind: "reject" });

    controller.abort();
    await expect(delay(1, controller.signal)).resolves.toBeUndefined();
  });

  it("executes permission summaries and redaction", () => {
    const shell = summarizePermission(
      {
        kind: "shell",
        fullCommandText: `echo ghp_${"x".repeat(24)}`,
        possiblePaths: [process.cwd()],
        possibleUrls: [{ url: "https://example.test/path" }],
        commands: [{ identifier: "echo" }],
      } as unknown as PermissionRequest,
      process.cwd(),
      "personal",
    );
    expect(shell.summary).toContain("<redacted:token>");
    expect(
      summarizePermission(
        {
          kind: "write",
          fileName: path.join(process.cwd(), "README.md"),
          intention: "update",
        } as unknown as PermissionRequest,
        process.cwd(),
        "personal",
      ).kind,
    ).toBe("write");
    expect(
      summarizePermission(
        {
          kind: "read",
          path: path.join(process.cwd(), "README.md"),
          intention: "read",
        } as unknown as PermissionRequest,
        process.cwd(),
        "personal",
      ).kind,
    ).toBe("read");
    expect(
      summarizePermission(
        {
          kind: "mcp",
          serverName: "server",
          toolName: "tool",
          readOnly: true,
        } as unknown as PermissionRequest,
        process.cwd(),
        "personal",
      ).kind,
    ).toBe("mcp");
    expect(
      summarizePermission(
        { kind: "unknown" } as unknown as PermissionRequest,
        process.cwd(),
        "personal",
      ).kind,
    ).toBe("unknown");
    expect(displayPath(process.cwd(), process.cwd(), "personal")).toBe(
      "personal/",
    );
    expect(displayPath(os.homedir(), process.cwd(), "personal")).toBe(
      "<outside-allowed-workspace>",
    );
    expect(safeHost("not a url")).toBe("<invalid-host>");
    expect(redactInline("Bearer secret")).toBe("******");
    expect(samePath(process.cwd(), process.cwd())).toBe(true);
  });

  it("executes inbound command, Copilot turn, and polling paths", async () => {
    const directory = await createTemporaryDirectory("inbound-runtime-");
    const tokenPath = path.join(directory, "auth-token");
    await writeFile(tokenPath, "a".repeat(40), "utf8");
    const client = new GatewayClient({
      baseUrl: "http://127.0.0.1:32147",
      tokenPath,
    });
    vi.spyOn(client, "status").mockResolvedValue({
      workspaceAliases: [
        {
          alias: "personal",
          path: process.cwd(),
          classification: "personal",
        },
      ],
    });
    vi.spyOn(client, "sendOutbound").mockResolvedValue({});
    vi.spyOn(client, "complete").mockResolvedValue({});
    const session = {
      sessionId: "session",
      sendAndWait: vi.fn(async () => ({
        data: { content: "safe response" },
      })),
      log: vi.fn(async () => undefined),
    } as unknown as CopilotSession;
    const activeTurns: unknown[] = [];
    const options = {
      client,
      session,
      signal: new AbortController().signal,
      workspacePath: process.cwd(),
      setActiveTurn: (turn: unknown) => activeTurns.push(turn),
    };
    const baseLease = {
      id: 1,
      leaseId: "lease",
      workspaceAlias: "personal",
      message: {
        tenantId: "local",
        channelId: "weixin-main",
        accountId: "bot",
        conversationId: "conversation",
        senderId: "sender",
        messageId: "message",
        text: "/help",
      },
    };
    await processInboundTurn(baseLease, options);
    await processInboundTurn(
      {
        ...baseLease,
        message: { ...baseLease.message, text: "/status" },
      },
      options,
    );
    await processInboundTurn(
      {
        ...baseLease,
        message: { ...baseLease.message, text: "answer this" },
      },
      options,
    );
    expect(session.sendAndWait).toHaveBeenCalledOnce();
    expect(activeTurns).toContainEqual(
      expect.objectContaining({ sessionId: "session" }),
    );

    vi.spyOn(client, "status").mockResolvedValueOnce({
      workspaceAliases: [],
    });
    await processInboundTurn(baseLease, options);
    expect(client.complete).toHaveBeenCalledWith(
      1,
      "lease",
      "failed",
      "REMOTE_TURN_FAILED",
      false,
    );

    const controller = new AbortController();
    vi.spyOn(client, "lease").mockResolvedValue({ message: null });
    await runInboundLoop({
      ...options,
      signal: controller.signal,
      wait: async () => {
        controller.abort();
      },
    });
    expect(client.lease).toHaveBeenCalledWith("session");
  });

  it("executes the authenticated loopback Canvas routes", async () => {
    const directory = await createTemporaryDirectory("canvas-runtime-");
    const tokenPath = path.join(directory, "auth-token");
    await writeFile(tokenPath, "a".repeat(40), "utf8");
    const client = new GatewayClient({
      baseUrl: "http://127.0.0.1:32147",
      tokenPath,
    });
    vi.spyOn(client, "status").mockResolvedValue({
      channels: [
        {
          id: "weixin-main",
          health: { state: "ready", accountLabel: "bot-account" },
          login: { accountId: "bot-account", userId: "personal-user" },
        },
      ],
      workspaceAliases: [],
      allowedSenders: [],
      bindings: [],
      pendingApprovals: [],
    });
    vi.spyOn(client, "ensureCompatible").mockResolvedValue({
      apiVersion: 2,
      capabilities: requiredGatewayCapabilities,
    });
    const request = vi
      .spyOn(client, "request")
      .mockImplementation(async (pathname) => ({ pathname }));
    const canvas = createAdminCanvas({
      client,
      getSessionContext: () => ({
        sessionId: "session",
        workspacePath: process.cwd(),
      }),
    });
    const context = {
      sessionId: "session",
      extensionId: "im-gateway",
      canvasId: "im-gateway-admin",
      instanceId: `coverage-${randomUUID()}`,
    };
    const opened = await canvas.open?.(context);
    if (opened === undefined || typeof opened.url !== "string") {
      throw new Error("Canvas did not return an open result.");
    }
    const url = new URL(opened.url);
    const token = url.searchParams.get("token");
    expect(url.hostname).toBe("127.0.0.1");
    const html = await fetch(url).then((response) => response.text());
    expect(html).toContain("accountLabel");
    expect(html).toContain("prefillLoginIdentity");
    expect(html).toContain("#binding-form [name=conversationId]");
    expect(html).not.toContain("a".repeat(40));
    expect(
      await fetch(new URL("/api/status", url)).then(
        (response) => response.status,
      ),
    ).toBe(401);

    const headers = {
      "Content-Type": "application/json",
      "X-Canvas-Token": token ?? "",
    };
    expect(
      await fetch(new URL("/api/status", url), { headers }).then((response) =>
        response.json(),
      ),
    ).toMatchObject({
      channels: [
        {
          login: { accountId: "bot-account", userId: "personal-user" },
        },
      ],
    });
    await fetch(new URL("/api/audit", url), { headers });
    for (const [pathname, body] of [
      ["/api/login/start", {}],
      ["/api/login/poll", { verifyCode: "123456" }],
      ["/api/aliases", { alias: "personal", path: process.cwd() }],
      [
        "/api/senders",
        {
          tenantId: "local",
          channelId: "weixin-main",
          accountId: "bot",
          senderId: "sender",
        },
      ],
      [
        "/api/bindings",
        {
          channelId: "weixin-main",
          tenantId: "local",
          accountId: "bot",
          conversationId: "conversation",
          senderId: "sender",
          workspaceAlias: "personal",
        },
      ],
      ["/api/approvals", { requestId: "request", decision: "denied" }],
    ] as const) {
      expect(
        await fetch(new URL(pathname, url), {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        }).then((response) => response.status),
      ).toBe(200);
    }
    expect(
      await fetch(new URL("/api/missing", url), { headers }).then(
        (response) => response.status,
      ),
    ).toBe(404);
    expect(request).toHaveBeenCalled();
    expect(
      request.mock.calls.map(([pathname]) => pathname),
    ).toEqual(
      expect.arrayContaining([
        "/v2/audit?limit=100",
        "/v2/channels/weixin-main/login/start",
        "/v2/channels/weixin-main/login/poll",
        "/v2/workspace-aliases",
        "/v2/allowed-senders",
        "/v2/bindings",
        "/v2/approvals/admin-decision",
      ]),
    );

    await canvas.onClose?.(context);
  });
});

async function createTemporaryDirectory(prefix: string) {
  const directory = await mkdtemp(path.join(os.tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}
