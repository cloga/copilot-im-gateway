import {
  chmodSync,
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { createBearerToken } from "../core/security.js";

export interface GatewayPaths {
  dataDirectory: string;
  databasePath: string;
  tokenPath: string;
}

export function resolveGatewayPaths(
  environment: NodeJS.ProcessEnv = process.env,
): GatewayPaths {
  const dataDirectory = path.resolve(
    environment.COPILOT_IM_GATEWAY_DATA_DIR ??
      path.join(os.homedir(), ".copilot-im-gateway"),
  );
  const tokenPath = path.resolve(
    environment.COPILOT_IM_GATEWAY_TOKEN_FILE ??
      path.join(dataDirectory, "auth-token"),
  );
  return {
    dataDirectory,
    databasePath: path.join(dataDirectory, "gateway.sqlite"),
    tokenPath,
  };
}

export function loadOrCreateBearerToken(tokenPath: string): string {
  mkdirSync(path.dirname(tokenPath), { recursive: true });
  try {
    const existing = readFileSync(tokenPath, "utf8").trim();
    if (existing.length < 32) {
      throw new Error(`Gateway token file '${tokenPath}' is invalid.`);
    }
    chmodSync(tokenPath, 0o600);
    return existing;
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code !== "ENOENT"
    ) {
      throw error;
    }
  }

  const token = createBearerToken();
  const descriptor = openSync(tokenPath, "wx", 0o600);
  try {
    writeFileSync(descriptor, `${token}\n`, { encoding: "utf8" });
  } finally {
    closeSync(descriptor);
  }
  chmodSync(tokenPath, 0o600);
  return token;
}
