import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

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
    const payload = await response.json();
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
      throw new Error(`Gateway request failed: ${code}`);
    }
    return payload;
  }

  status() {
    return this.request("/v1/status");
  }

  /** @param {string} sessionId */
  lease(sessionId) {
    return this.request("/v1/messages/lease", {
      method: "POST",
      body: JSON.stringify({ sessionId, leaseSeconds: 90 }),
    });
  }

  /**
   * @param {number} id
   * @param {string} leaseId
   * @param {"completed"|"failed"} outcome
   * @param {string} [errorCode]
   */
  complete(id, leaseId, outcome, errorCode) {
    return this.request(`/v1/messages/${id}/complete`, {
      method: "POST",
      body: JSON.stringify({
        leaseId,
        outcome,
        ...(errorCode === undefined ? {} : { errorCode }),
      }),
    });
  }

  /**
   * @param {{channelId:string, conversationId:string, correlationId:string, text:string}} message
   */
  sendOutbound(message) {
    return this.request("/v1/outbound", {
      method: "POST",
      body: JSON.stringify(message),
    });
  }

  /** @param {Record<string, unknown>} approval */
  createApproval(approval) {
    return this.request("/v1/approvals", {
      method: "POST",
      body: JSON.stringify(approval),
    });
  }

  /** @param {string} requestId @param {string} sessionId */
  consumeApproval(requestId, sessionId) {
    return this.request("/v1/approvals/consume", {
      method: "POST",
      body: JSON.stringify({ requestId, sessionId }),
    });
  }
}
