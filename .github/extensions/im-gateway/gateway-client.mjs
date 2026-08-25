import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export const supportedGatewayApiVersion = 2;
export const requiredGatewayCapabilities = [
  "account-scoped-routing",
  "sender-bound-routing",
  "operation-bound-approvals",
  "reservation-ownership",
];

export class GatewayClientError extends Error {
  /** @param {string} code @param {string} message @param {number} [status] */
  constructor(code, message, status) {
    super(message);
    this.name = "GatewayClientError";
    this.code = code;
    this.status = status;
  }
}

export function resolveGatewayConnection() {
  const dataDirectory = path.resolve(
    process.env.COPILOT_IM_GATEWAY_DATA_DIR ??
      path.join(os.homedir(), ".copilot-im-gateway"),
  );
  const tokenPath = path.resolve(
    process.env.COPILOT_IM_GATEWAY_TOKEN_FILE ??
      path.join(dataDirectory, "auth-token"),
  );
  return {
    baseUrl:
      process.env.COPILOT_IM_GATEWAY_URL ?? "http://127.0.0.1:32147",
    tokenPath,
  };
}

export class GatewayClient {
  /** @param {{baseUrl: string, tokenPath: string}} options */
  constructor(options) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.tokenPath = options.tokenPath;
  }

  /** @param {string} pathname @param {RequestInit} [init] */
  async request(pathname, init = {}) {
    const token = readFileSync(this.tokenPath, "utf8").trim();
    if (token.length < 32) {
      throw new Error(`Gateway token file '${this.tokenPath}' is invalid.`);
    }
    const response = await fetch(`${this.baseUrl}${pathname}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...init.headers,
      },
    });
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new GatewayClientError(
        `HTTP_${response.status}`,
        "Gateway returned an invalid JSON response.",
        response.status,
      );
    }
    if (!response.ok) {
      const code =
        typeof payload === "object" &&
        payload !== null &&
        "error" in payload &&
        typeof payload.error === "object" &&
        payload.error !== null &&
        "code" in payload.error
          ? String(payload.error.code)
          : `HTTP_${response.status}`;
      throw new GatewayClientError(
        code,
        `Gateway request failed: ${code}`,
        response.status,
      );
    }
    return payload;
  }

  async ensureCompatible() {
    return this.#loadCompatibility();
  }

  async #loadCompatibility() {
    let status;
    try {
      status = await this.request("/v2/status");
    } catch (error) {
      if (
        error instanceof GatewayClientError &&
        (error.status === 404 || error.code === "NOT_FOUND")
      ) {
        throw this.#daemonUpgradeRequired();
      }
      throw error;
    }
    if (
      typeof status !== "object" ||
      status === null ||
      status.apiVersion !== supportedGatewayApiVersion ||
      !Array.isArray(status.capabilities) ||
      !requiredGatewayCapabilities.every((capability) =>
        status.capabilities.includes(capability),
      )
    ) {
      throw this.#daemonUpgradeRequired();
    }
    return status;
  }

  #daemonUpgradeRequired() {
    return new GatewayClientError(
      "DAEMON_UPGRADE_REQUIRED",
      "DAEMON_UPGRADE_REQUIRED: upgrade the installed IM Gateway daemon with this extension.",
      426,
    );
  }

  async status() {
    return this.ensureCompatible();
  }

  async audit() {
    await this.ensureCompatible();
    return this.request("/v2/audit?limit=100");
  }

  async startLogin() {
    await this.ensureCompatible();
    return this.request("/v2/channels/weixin-main/login/start", {
      method: "POST",
      body: "{}",
    });
  }

  /** @param {Record<string, unknown>} input */
  async pollLogin(input) {
    await this.ensureCompatible();
    return this.request("/v2/channels/weixin-main/login/poll", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  /** @param {Record<string, unknown>} input */
  async upsertWorkspaceAlias(input) {
    await this.ensureCompatible();
    return this.request("/v2/workspace-aliases", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  /** @param {Record<string, unknown>} input */
  async allowSender(input) {
    await this.ensureCompatible();
    return this.request("/v2/allowed-senders", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  /** @param {Record<string, unknown>} input */
  async upsertBinding(input) {
    await this.ensureCompatible();
    return this.request("/v2/bindings", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  /** @param {Record<string, unknown>} input */
  async decideApprovalByAdmin(input) {
    await this.ensureCompatible();
    return this.request("/v2/approvals/admin-decision", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  /** @param {string} sessionId */
  async lease(sessionId) {
    await this.ensureCompatible();
    return this.request("/v2/messages/lease", {
      method: "POST",
      body: JSON.stringify({ sessionId, leaseSeconds: 90 }),
    });
  }

  /**
   * @param {number} id
   * @param {string} leaseId
   * @param {"completed"|"failed"} outcome
   * @param {string} [errorCode]
   * @param {boolean} [retryable]
   */
  async complete(id, leaseId, outcome, errorCode, retryable = false) {
    await this.ensureCompatible();
    return this.request(`/v2/messages/${id}/complete`, {
      method: "POST",
      body: JSON.stringify({
        leaseId,
        outcome,
        ...(errorCode === undefined ? {} : { errorCode }),
        retryable,
      }),
    });
  }

  /**
   * @param {{tenantId:string, channelId:string, accountId:string, conversationId:string, senderId:string, correlationId:string, text:string}} message
   */
  async sendOutbound(message) {
    await this.ensureCompatible();
    return this.request("/v2/outbound", {
      method: "POST",
      body: JSON.stringify(message),
    });
  }

  /** @param {Record<string, unknown>} approval */
  async createApproval(approval) {
    await this.ensureCompatible();
    return this.request("/v2/approvals", {
      method: "POST",
      body: JSON.stringify(approval),
    });
  }

  /** @param {string} requestId @param {Record<string, string>} identity @param {string} operationDigest */
  async consumeApproval(requestId, identity, operationDigest) {
    await this.ensureCompatible();
    return this.request("/v2/approvals/consume", {
      method: "POST",
      body: JSON.stringify({ requestId, identity, operationDigest }),
    });
  }
}
