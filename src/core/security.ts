import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import path from "node:path";
import {
  canonicalizeIdentityComponents,
  type TenantId,
} from "./contracts.js";

export interface RemoteIdentity {
  tenantId: TenantId;
  channelId: string;
  accountId: string;
  conversationId: string;
  senderId: string;
  sessionId: string;
}

export interface PermissionScope {
  kind: string;
  summary: string;
  paths: string[];
  hosts: string[];
  commands: string[];
}

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

export function createBearerToken(): string {
  return randomBytes(32).toString("base64url");
}

export function createApprovalNonce(): string {
  return randomBytes(18).toString("base64url");
}

export function hashSecret(value: string, label = "secret"): string {
  return createHash("sha256")
    .update(`${Buffer.byteLength(label, "utf8")}:${label}`)
    .update(`${Buffer.byteLength(value, "utf8")}:${value}`)
    .digest("hex");
}

export function digestPermissionScope(scope: PermissionScope): string {
  return hashSecret(
    canonicalizeIdentityComponents([
      scope.kind,
      "paths",
      String(scope.paths.length),
      ...[...scope.paths].sort(),
      "hosts",
      String(scope.hosts.length),
      ...[...scope.hosts].sort(),
      "commands",
      String(scope.commands.length),
      ...[...scope.commands].sort(),
    ]),
    "approval-scope",
  );
}

export function digestApprovalOperation(
  requestId: string,
  scope: PermissionScope,
): string {
  return hashSecret(
    canonicalizeIdentityComponents([
      requestId,
      digestPermissionScope(scope),
    ]),
    "approval-operation",
  );
}

export function constantTimeTokenEqual(
  actual: string | undefined,
  expected: string,
): boolean {
  if (actual === undefined) {
    return false;
  }
  const actualHash = createHash("sha256").update(actual).digest();
  const expectedHash = createHash("sha256").update(expected).digest();
  return timingSafeEqual(actualHash, expectedHash);
}

const redactionPatterns: ReadonlyArray<[RegExp, string]> = [
  [/\bgh[opsu]_[A-Za-z0-9_]{20,}\b/g, "<redacted:github-token>"],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "<redacted:github-token>"],
  [/\bBearer\s+[A-Za-z0-9._~+/-]+=*\b/gi, "Bearer <redacted:token>"],
  [
    /\b(api[_-]?key|client[_-]?secret|access[_-]?token|password)\s*[:=]\s*["']?[^\s"',;]+/gi,
    "$1=<redacted:secret>",
  ],
  [
    /(?:[A-Za-z]:\\(?:[^\\\r\n<>:"|?*]+\\)+[^\\\r\n<>:"|?*]*|\/(?:Users|home|var|etc|opt|private|mnt)\/[^\s"'<>]+)/g,
    "<redacted:path>",
  ],
];

export function redactText(value: string): string {
  return redactionPatterns.reduce(
    (redacted, [pattern, replacement]) =>
      redacted.replace(pattern, replacement),
    value,
  );
}

export function chunkOutboundText(
  value: string,
  maxChunkCharacters = 1800,
  maxChunks = 8,
): string[] {
  const normalized = redactText(value).replace(/\r\n/g, "\n").trim();
  if (normalized.length === 0) {
    return [];
  }

  const maxTotal = maxChunkCharacters * maxChunks;
  const bounded =
    normalized.length > maxTotal
      ? `${normalized.slice(0, maxTotal - 24)}\n[output truncated]`
      : normalized;
  const chunks: string[] = [];
  let remaining = bounded;

  while (remaining.length > maxChunkCharacters && chunks.length < maxChunks) {
    const candidate = remaining.slice(0, maxChunkCharacters);
    const splitAt = Math.max(
      candidate.lastIndexOf("\n"),
      candidate.lastIndexOf(" "),
    );
    const boundary =
      splitAt >= Math.floor(maxChunkCharacters * 0.6)
        ? splitAt
        : maxChunkCharacters;
    chunks.push(remaining.slice(0, boundary).trim());
    remaining = remaining.slice(boundary).trimStart();
  }
  if (remaining.length > 0 && chunks.length < maxChunks) {
    chunks.push(remaining);
  }
  return chunks;
}

export function canonicalizeWorkspace(candidate: string): string {
  return path.resolve(candidate);
}

export function isPathInside(root: string, candidate: string): boolean {
  const canonicalRoot = canonicalizeWorkspace(root);
  const canonicalCandidate = canonicalizeWorkspace(candidate);
  const relative = path.relative(canonicalRoot, canonicalCandidate);
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative))
  );
}
