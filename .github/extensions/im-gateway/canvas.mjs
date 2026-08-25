import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { createCanvas } from "@github/copilot-sdk/extension";

const servers = new Map();

/** @param {string} actual @param {string} expected */
function safeEqual(actual, expected) {
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);
  return (
    actualBuffer.length === expectedBuffer.length &&
    timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

function renderHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>IM Gateway</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; padding: 20px; background: Canvas; color: CanvasText; }
    header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    h1, h2 { margin: 0 0 12px; }
    h1 { font-size: 22px; } h2 { font-size: 16px; }
    main { display: grid; gap: 16px; margin-top: 18px; }
    section { border: 1px solid color-mix(in srgb, CanvasText 18%, transparent); border-radius: 10px; padding: 14px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px; }
    form { display: grid; gap: 8px; }
    input, select, button { font: inherit; padding: 8px 10px; border-radius: 6px; border: 1px solid color-mix(in srgb, CanvasText 25%, transparent); }
    button { cursor: pointer; background: AccentColor; color: AccentColorText; border: 0; }
    button.secondary { background: color-mix(in srgb, CanvasText 10%, Canvas); color: CanvasText; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 260px; overflow: auto; }
    .badge { display: inline-block; border-radius: 999px; padding: 3px 8px; background: color-mix(in srgb, AccentColor 20%, Canvas); }
    .muted { opacity: .72; font-size: 13px; }
    .approval { border-top: 1px solid color-mix(in srgb, CanvasText 15%, transparent); padding: 10px 0; }
    .approval:first-child { border-top: 0; }
    #qr img { max-width: 240px; background: white; padding: 8px; border-radius: 8px; }
    #notice { min-height: 20px; color: #b45309; }
  </style>
</head>
<body>
  <header>
    <div><h1>Copilot IM Gateway</h1><div class="muted">Local-only administration</div></div>
    <button id="refresh" class="secondary">Refresh</button>
  </header>
  <div id="notice"></div>
  <main>
    <section><h2>Channel health</h2><div id="channels" class="grid"></div></section>
    <section>
      <h2>WeChat login</h2>
      <div class="grid">
        <div><button id="login-start">Start QR login</button><div id="qr"></div></div>
        <form id="verify-form"><input name="verifyCode" inputmode="numeric" placeholder="Pairing code" /><button>Submit and poll</button></form>
      </div>
    </section>
    <section>
      <h2>Policy</h2>
      <div class="grid">
        <form id="alias-form"><strong>Workspace alias</strong><input name="alias" placeholder="personal-repo" required /><input name="path" placeholder="C:\\path\\to\\repo" required /><button>Save personal alias</button></form>
        <form id="sender-form"><strong>Allowed sender</strong><input name="tenantId" value="local" required /><input name="channelId" value="weixin-main" required /><input name="accountId" placeholder="Negotiated bot account ID" required /><input name="senderId" placeholder="WeChat user ID" required /><button>Allow sender</button></form>
        <form id="binding-form"><strong>Session binding</strong><input name="tenantId" value="local" required /><input name="channelId" value="weixin-main" required /><input name="accountId" placeholder="Negotiated bot account ID" required /><input name="conversationId" placeholder="WeChat conversation/user ID" required /><input name="senderId" placeholder="Conversation owner ID" required /><input name="workspaceAlias" placeholder="personal-repo" required /><button>Bind current session</button></form>
      </div>
    </section>
    <section><h2>Pending approvals</h2><div id="approvals"></div></section>
    <section><h2>Bindings and aliases</h2><pre id="configuration"></pre></section>
    <section><h2>Recent audit events</h2><pre id="audit"></pre></section>
  </main>
  <script>
    const canvasToken = new URL(location.href).searchParams.get("token");
    const notice = document.querySelector("#notice");
    async function api(path, init = {}) {
      const response = await fetch(path, {
        ...init,
        headers: { "Content-Type": "application/json", "X-Canvas-Token": canvasToken, ...(init.headers || {}) },
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Request failed");
      return payload;
    }
    function esc(value) {
      return String(value).replace(/[&<>"']/g, character => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      })[character]);
    }
    function safeImageUrl(value) {
      try {
        const parsed = new URL(value);
        return parsed.protocol === "https:" || parsed.protocol === "data:" ? esc(parsed.href) : "";
      } catch { return ""; }
    }
    function values(form) { return Object.fromEntries(new FormData(form).entries()); }
    async function refresh() {
      notice.textContent = "";
      try {
        const [status, audit] = await Promise.all([api("/api/status"), api("/api/audit")]);
        document.querySelector("#channels").innerHTML = status.channels.map(channel =>
          '<div><span class="badge">' + esc(channel.id) + '</span><p>' + esc(channel.health.state) + '</p></div>'
        ).join("");
        document.querySelector("#configuration").textContent = JSON.stringify({
          workspaceAliases: status.workspaceAliases,
          allowedSenders: status.allowedSenders,
          bindings: status.bindings,
        }, null, 2);
        document.querySelector("#audit").textContent = JSON.stringify(audit.events, null, 2);
        document.querySelector("#approvals").innerHTML = status.pendingApprovals.length === 0
          ? '<div class="muted">No pending approvals.</div>'
          : status.pendingApprovals.map(approval =>
              '<div class="approval"><strong>' + esc(approval.scope.kind) + '</strong><p>' +
              esc(approval.scope.summary) + '</p><button data-decision="approved" data-id="' +
              esc(approval.requestId) + '">Approve once</button> <button class="secondary" data-decision="denied" data-id="' +
              esc(approval.requestId) + '">Deny</button></div>'
            ).join("");
      } catch (error) { notice.textContent = String(error); }
    }
    async function post(path, body) {
      await api(path, { method: "POST", body: JSON.stringify(body) });
      await refresh();
    }
    document.querySelector("#refresh").onclick = refresh;
    document.querySelector("#login-start").onclick = async () => {
      const result = await api("/api/login/start", { method: "POST", body: "{}" });
      const qrUrl = result.qrCodeUrl ? safeImageUrl(result.qrCodeUrl) : "";
      document.querySelector("#qr").innerHTML = qrUrl
        ? '<p>' + esc(result.state) + '</p><img alt="WeChat login QR" src="' + qrUrl + '" />'
        : '<p>' + esc(result.state) + '</p>';
      await refresh();
    };
    document.querySelector("#verify-form").onsubmit = async event => {
      event.preventDefault();
      const result = await api("/api/login/poll", { method: "POST", body: JSON.stringify(values(event.currentTarget)) });
      const qrUrl = result.qrCodeUrl ? safeImageUrl(result.qrCodeUrl) : "";
      document.querySelector("#qr").innerHTML = '<p>' + esc(result.state) + '</p>' +
        (qrUrl ? '<img alt="WeChat login QR" src="' + qrUrl + '" />' : "");
      await refresh();
    };
    document.querySelector("#alias-form").onsubmit = async event => { event.preventDefault(); await post("/api/aliases", values(event.currentTarget)); };
    document.querySelector("#sender-form").onsubmit = async event => { event.preventDefault(); await post("/api/senders", values(event.currentTarget)); };
    document.querySelector("#binding-form").onsubmit = async event => { event.preventDefault(); await post("/api/bindings", values(event.currentTarget)); };
    document.querySelector("#approvals").onclick = async event => {
      const button = event.target.closest("button[data-decision]");
      if (button) await post("/api/approvals", { requestId: button.dataset.id, decision: button.dataset.decision });
    };
    void refresh();
  </script>
</body>
</html>`;
}

/**
 * @param {{
 *   client: import("./gateway-client.mjs").GatewayClient,
 *   getSessionContext: () => {sessionId:string, workspacePath:string}
 * }} options
 */
export function createAdminCanvas(options) {
  return createCanvas({
    id: "im-gateway-admin",
    displayName: "IM Gateway",
    description:
      "Administer the local WeChat gateway, bindings, approvals, and audit status.",
    actions: [
      {
        name: "refresh_status",
        description: "Return the current local gateway status.",
        handler: async () => options.client.status(),
      },
    ],
    open: async (context) => {
      let entry = servers.get(context.instanceId);
      if (entry === undefined) {
        entry = await startCanvasServer(options);
        servers.set(context.instanceId, entry);
      }
      return {
        title: "Copilot IM Gateway",
        url: `${entry.url}/?token=${encodeURIComponent(entry.secret)}`,
      };
    },
    onClose: async (context) => {
      const entry = servers.get(context.instanceId);
      if (entry !== undefined) {
        servers.delete(context.instanceId);
        await new Promise((resolve, reject) => {
          entry.server.close(
            /** @param {Error | undefined} error */
            (error) =>
              error === undefined ? resolve(undefined) : reject(error),
          );
        });
      }
    },
  });
}

/** @param {Parameters<typeof createAdminCanvas>[0]} options */
async function startCanvasServer(options) {
  const secret = randomBytes(24).toString("base64url");
  const server = createServer((request, response) => {
    void handleCanvasRequest(options, secret, request, response);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve(undefined);
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Canvas server did not expose a TCP port.");
  }
  return { server, secret, url: `http://127.0.0.1:${address.port}` };
}

/**
 * @param {Parameters<typeof createAdminCanvas>[0]} options
 * @param {string} secret
 * @param {import("node:http").IncomingMessage} request
 * @param {import("node:http").ServerResponse} response
 */
async function handleCanvasRequest(options, secret, request, response) {
  try {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method === "GET" && url.pathname === "/") {
      response.setHeader("Content-Type", "text/html; charset=utf-8");
      response.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; img-src https: data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
      );
      response.end(renderHtml());
      return;
    }
    const provided = String(request.headers["x-canvas-token"] ?? "");
    if (!safeEqual(provided, secret)) {
      sendJson(response, 401, { error: "Canvas authentication required." });
      return;
    }
    const method = request.method ?? "GET";
    if (method === "GET" && url.pathname === "/api/status") {
      sendJson(response, 200, await options.client.status());
      return;
    }
    if (method === "GET" && url.pathname === "/api/audit") {
      sendJson(response, 200, await options.client.request("/v1/audit?limit=100"));
      return;
    }
    const body = method === "POST" ? await readBody(request) : {};
    if (method === "POST" && url.pathname === "/api/login/start") {
      sendJson(
        response,
        200,
        await options.client.request("/v1/channels/weixin-main/login/start", {
          method: "POST",
          body: "{}",
        }),
      );
      return;
    }
    if (method === "POST" && url.pathname === "/api/login/poll") {
      sendJson(
        response,
        200,
        await options.client.request("/v1/channels/weixin-main/login/poll", {
          method: "POST",
          body: JSON.stringify(body),
        }),
      );
      return;
    }
    if (method === "POST" && url.pathname === "/api/aliases") {
      sendJson(
        response,
        200,
        await options.client.request("/v1/workspace-aliases", {
          method: "POST",
          body: JSON.stringify({ ...body, classification: "personal" }),
        }),
      );
      return;
    }
    if (method === "POST" && url.pathname === "/api/senders") {
      sendJson(
        response,
        200,
        await options.client.request("/v1/allowed-senders", {
          method: "POST",
          body: JSON.stringify(body),
        }),
      );
      return;
    }
    if (method === "POST" && url.pathname === "/api/bindings") {
      const session = options.getSessionContext();
      sendJson(
        response,
        200,
        await options.client.request("/v1/bindings", {
          method: "POST",
          body: JSON.stringify({ ...body, sessionId: session.sessionId }),
        }),
      );
      return;
    }
    if (method === "POST" && url.pathname === "/api/approvals") {
      sendJson(
        response,
        200,
        await options.client.request("/v1/approvals/admin-decision", {
          method: "POST",
          body: JSON.stringify(body),
        }),
      );
      return;
    }
    sendJson(response, 404, { error: "Canvas endpoint not found." });
  } catch (error) {
    sendJson(response, 500, { error: error instanceof Error ? error.message : "Canvas request failed." });
  }
}

/** @param {import("node:http").IncomingMessage} request */
async function readBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += buffer.length;
    if (length > 256 * 1024) {
      throw new Error("Canvas request body exceeds 256 KiB.");
    }
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

/** @param {import("node:http").ServerResponse} response @param {number} status @param {unknown} payload */
function sendJson(response, status, payload) {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  response.end(JSON.stringify(payload));
}
