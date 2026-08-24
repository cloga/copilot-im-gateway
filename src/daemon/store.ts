import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type {
  ImInboundMessage,
  SessionBinding,
} from "../core/contracts.js";
import { toRouteKey } from "../core/contracts.js";
import { GatewayError, gatewayErrorCodes } from "../core/errors.js";
import type {
  PermissionScope,
  RemoteIdentity,
} from "../core/security.js";
import { canonicalizeWorkspace, hashSecret } from "../core/security.js";

interface CountRow {
  count: number;
}

interface InboundRow {
  id: number;
  channel_id: string;
  conversation_id: string;
  message_id: string;
  sender_id: string;
  received_at: string;
  text: string;
  attachments_json: string;
  reply_to_message_id: string | null;
  workspace_alias: string;
}

interface ApprovalRow {
  request_id: string;
  status: "pending" | "approved" | "denied" | "consumed";
  expires_at: string;
  identity_json: string;
  scope_json: string;
}

export interface LeasedInboundMessage {
  id: number;
  leaseId: string;
  message: ImInboundMessage;
  workspaceAlias: string;
}

export interface ApprovalRecord {
  requestId: string;
  status: "pending" | "approved" | "denied" | "consumed";
  expiresAt: string;
  identity: RemoteIdentity;
  scope: PermissionScope;
}

export interface AuditEvent {
  id: number;
  createdAt: string;
  eventType: string;
  actor: string;
  routeKey?: string;
  details: Readonly<Record<string, unknown>>;
}

export class GatewayStore {
  readonly #database: DatabaseSync;

  constructor(databasePath: string) {
    mkdirSync(path.dirname(databasePath), { recursive: true });
    this.#database = new DatabaseSync(databasePath);
    this.#database.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
    this.#migrate();
  }

  close(): void {
    this.#database.close();
  }

  #migrate(): void {
    this.#database.exec(`
      CREATE TABLE IF NOT EXISTS workspace_aliases (
        alias TEXT PRIMARY KEY,
        canonical_path TEXT NOT NULL,
        classification TEXT NOT NULL CHECK (classification IN ('personal', 'work')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS allowed_senders (
        channel_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        display_name TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (channel_id, sender_id)
      );
      CREATE TABLE IF NOT EXISTS session_bindings (
        route_key TEXT PRIMARY KEY,
        channel_id TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        workspace_alias TEXT NOT NULL REFERENCES workspace_aliases(alias),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS inbound_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        received_at TEXT NOT NULL,
        text TEXT NOT NULL,
        attachments_json TEXT NOT NULL,
        reply_to_message_id TEXT,
        status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'completed', 'failed')),
        lease_id TEXT,
        lease_expires_at TEXT,
        error_code TEXT,
        created_at TEXT NOT NULL,
        UNIQUE (channel_id, message_id)
      );
      CREATE INDEX IF NOT EXISTS idx_inbound_status
        ON inbound_messages(status, created_at);
      CREATE TABLE IF NOT EXISTS approvals (
        request_id TEXT PRIMARY KEY,
        nonce_hash TEXT NOT NULL UNIQUE,
        identity_json TEXT NOT NULL,
        scope_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        decided_at TEXT,
        consumed_at TEXT
      );
      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        event_type TEXT NOT NULL,
        actor TEXT NOT NULL,
        route_key TEXT,
        details_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_created_at
        ON audit_events(created_at DESC);
      CREATE TABLE IF NOT EXISTS channel_state (
        channel_id TEXT NOT NULL,
        state_key TEXT NOT NULL,
        value_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (channel_id, state_key)
      );
    `);
  }

  transaction<T>(operation: () => T): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      this.#database.exec("ROLLBACK");
      throw error;
    }
  }

  upsertWorkspaceAlias(
    alias: string,
    workspacePath: string,
    classification: "personal" | "work",
    now: string,
  ): void {
    const canonicalPath = canonicalizeWorkspace(workspacePath);
    this.#database
      .prepare(
        `INSERT INTO workspace_aliases
          (alias, canonical_path, classification, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(alias) DO UPDATE SET
          canonical_path = excluded.canonical_path,
          classification = excluded.classification,
          updated_at = excluded.updated_at`,
      )
      .run(alias, canonicalPath, classification, now, now);
  }

  getWorkspaceAlias(alias: string):
    | { alias: string; path: string; classification: "personal" | "work" }
    | undefined {
    const row = this.#database
      .prepare(
        `SELECT alias, canonical_path AS path, classification
         FROM workspace_aliases WHERE alias = ?`,
      )
      .get(alias) as
      | {
          alias: string;
          path: string;
          classification: "personal" | "work";
        }
      | undefined;
    return row;
  }

  listWorkspaceAliases(): Array<{
    alias: string;
    path: string;
    classification: "personal" | "work";
  }> {
    return this.#database
      .prepare(
        `SELECT alias, canonical_path AS path, classification
         FROM workspace_aliases ORDER BY alias`,
      )
      .all() as Array<{
      alias: string;
      path: string;
      classification: "personal" | "work";
    }>;
  }

  allowSender(
    channelId: string,
    senderId: string,
    displayName: string | undefined,
    now: string,
  ): void {
    this.#database
      .prepare(
        `INSERT INTO allowed_senders
          (channel_id, sender_id, display_name, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(channel_id, sender_id) DO UPDATE SET
          display_name = excluded.display_name`,
      )
      .run(channelId, senderId, displayName ?? null, now);
  }

  isSenderAllowed(channelId: string, senderId: string): boolean {
    const row = this.#database
      .prepare(
        `SELECT COUNT(*) AS count FROM allowed_senders
         WHERE channel_id = ? AND sender_id = ?`,
      )
      .get(channelId, senderId) as unknown as CountRow;
    return row.count > 0;
  }

  listAllowedSenders(): Array<{
    channelId: string;
    senderId: string;
    displayName?: string;
  }> {
    const rows = this.#database
      .prepare(
        `SELECT channel_id, sender_id, display_name
         FROM allowed_senders ORDER BY channel_id, sender_id`,
      )
      .all() as Array<{
      channel_id: string;
      sender_id: string;
      display_name: string | null;
    }>;
    return rows.map((row) => ({
      channelId: row.channel_id,
      senderId: row.sender_id,
      ...(row.display_name === null
        ? {}
        : { displayName: row.display_name }),
    }));
  }

  upsertBinding(
    binding: Omit<SessionBinding, "routeKey" | "createdAt" | "updatedAt">,
    now: string,
  ): SessionBinding {
    const routeKey = toRouteKey(binding.channelId, binding.conversationId);
    this.#database
      .prepare(
        `INSERT INTO session_bindings
          (route_key, channel_id, conversation_id, session_id, workspace_alias, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(route_key) DO UPDATE SET
          session_id = excluded.session_id,
          workspace_alias = excluded.workspace_alias,
          updated_at = excluded.updated_at`,
      )
      .run(
        routeKey,
        binding.channelId,
        binding.conversationId,
        binding.sessionId,
        binding.workspaceAlias,
        now,
        now,
      );
    const row = this.#database
      .prepare(
        `SELECT route_key, channel_id, conversation_id, session_id,
                workspace_alias, created_at, updated_at
         FROM session_bindings WHERE route_key = ?`,
      )
      .get(routeKey) as {
      route_key: string;
      channel_id: string;
      conversation_id: string;
      session_id: string;
      workspace_alias: string;
      created_at: string;
      updated_at: string;
    };
    return {
      routeKey: row.route_key as SessionBinding["routeKey"],
      channelId: row.channel_id,
      conversationId: row.conversation_id,
      sessionId: row.session_id,
      workspaceAlias: row.workspace_alias,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  listBindings(): SessionBinding[] {
    const rows = this.#database
      .prepare(
        `SELECT route_key, channel_id, conversation_id, session_id,
                workspace_alias, created_at, updated_at
         FROM session_bindings ORDER BY route_key`,
      )
      .all() as Array<{
      route_key: string;
      channel_id: string;
      conversation_id: string;
      session_id: string;
      workspace_alias: string;
      created_at: string;
      updated_at: string;
    }>;
    return rows.map((row) => ({
      routeKey: row.route_key as SessionBinding["routeKey"],
      channelId: row.channel_id,
      conversationId: row.conversation_id,
      sessionId: row.session_id,
      workspaceAlias: row.workspace_alias,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  insertInbound(message: ImInboundMessage, now: string): boolean {
    const result = this.#database
      .prepare(
        `INSERT OR IGNORE INTO inbound_messages
          (channel_id, conversation_id, message_id, sender_id, received_at,
           text, attachments_json, reply_to_message_id, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
      )
      .run(
        message.channelId,
        message.conversationId,
        message.messageId,
        message.senderId,
        message.receivedAt,
        message.text,
        JSON.stringify(message.attachments),
        message.replyToMessageId ?? null,
        now,
      );
    return result.changes === 1;
  }

  leaseInbound(
    sessionId: string,
    now: string,
    leaseSeconds: number,
  ): LeasedInboundMessage | undefined {
    return this.transaction(() => {
      this.#database
        .prepare(
          `UPDATE inbound_messages
           SET status = 'pending', lease_id = NULL, lease_expires_at = NULL
           WHERE status = 'leased' AND lease_expires_at <= ?`,
        )
        .run(now);
      const row = this.#database
        .prepare(
          `SELECT m.id, m.channel_id, m.conversation_id, m.message_id,
                  m.sender_id, m.received_at, m.text, m.attachments_json,
                  m.reply_to_message_id, b.workspace_alias
           FROM inbound_messages m
           JOIN session_bindings b
             ON b.route_key = m.channel_id || ':' || m.conversation_id
           WHERE m.status = 'pending' AND b.session_id = ?
           ORDER BY m.created_at, m.id
           LIMIT 1`,
        )
        .get(sessionId) as InboundRow | undefined;
      if (row === undefined) {
        return undefined;
      }
      const leaseId = randomUUID();
      const leaseExpiresAt = new Date(
        new Date(now).getTime() + leaseSeconds * 1000,
      ).toISOString();
      this.#database
        .prepare(
          `UPDATE inbound_messages
           SET status = 'leased', lease_id = ?, lease_expires_at = ?
           WHERE id = ? AND status = 'pending'`,
        )
        .run(leaseId, leaseExpiresAt, row.id);
      return {
        id: row.id,
        leaseId,
        workspaceAlias: row.workspace_alias,
        message: {
          channelId: row.channel_id,
          conversationId: row.conversation_id,
          messageId: row.message_id,
          senderId: row.sender_id,
          receivedAt: row.received_at,
          text: row.text,
          attachments: JSON.parse(
            row.attachments_json,
          ) as ImInboundMessage["attachments"],
          ...(row.reply_to_message_id === null
            ? {}
            : { replyToMessageId: row.reply_to_message_id }),
        },
      };
    });
  }

  completeInbound(
    id: number,
    leaseId: string,
    outcome: "completed" | "failed",
    errorCode?: string,
  ): void {
    const result = this.#database
      .prepare(
        `UPDATE inbound_messages
         SET status = ?, error_code = ?, lease_id = NULL, lease_expires_at = NULL
         WHERE id = ? AND status = 'leased' AND lease_id = ?`,
      )
      .run(outcome, errorCode ?? null, id, leaseId);
    if (result.changes !== 1) {
      throw new GatewayError({
        code: gatewayErrorCodes.conflict,
        message: "Inbound lease is missing or no longer active.",
        status: 409,
      });
    }
  }

  createApproval(input: {
    requestId: string;
    nonce: string;
    identity: RemoteIdentity;
    scope: PermissionScope;
    expiresAt: string;
    now: string;
  }): void {
    this.#database
      .prepare(
        `INSERT INTO approvals
          (request_id, nonce_hash, identity_json, scope_json, status, expires_at, created_at)
         VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
      )
      .run(
        input.requestId,
        hashSecret(input.nonce),
        JSON.stringify(input.identity),
        JSON.stringify(input.scope),
        input.expiresAt,
        input.now,
      );
  }

  decideApproval(input: {
    nonce: string;
    identity: RemoteIdentity;
    decision: "approved" | "denied";
    now: string;
  }): ApprovalRecord {
    return this.transaction(() => {
      const row = this.#database
        .prepare(
          `SELECT request_id, status, expires_at, identity_json, scope_json
           FROM approvals WHERE nonce_hash = ?`,
        )
        .get(hashSecret(input.nonce)) as ApprovalRow | undefined;
      if (row === undefined) {
        throw new GatewayError({
          code: gatewayErrorCodes.approvalNotFound,
          message: "Approval nonce was not found.",
          status: 404,
        });
      }

      const identity = JSON.parse(row.identity_json) as RemoteIdentity;
      if (
        identity.channelId !== input.identity.channelId ||
        identity.conversationId !== input.identity.conversationId ||
        identity.senderId !== input.identity.senderId ||
        identity.sessionId !== input.identity.sessionId
      ) {
        throw new GatewayError({
          code: gatewayErrorCodes.approvalMismatch,
          message: "Approval nonce does not match this remote identity.",
          status: 403,
        });
      }
      if (new Date(row.expires_at).getTime() <= new Date(input.now).getTime()) {
        throw new GatewayError({
          code: gatewayErrorCodes.approvalExpired,
          message: "Approval nonce has expired.",
          status: 410,
        });
      }
      if (row.status !== "pending") {
        throw new GatewayError({
          code: gatewayErrorCodes.approvalReplayed,
          message: "Approval nonce has already been used.",
          status: 409,
        });
      }
      this.#database
        .prepare(
          `UPDATE approvals SET status = ?, decided_at = ?
           WHERE request_id = ? AND status = 'pending'`,
        )
        .run(input.decision, input.now, row.request_id);
      return {
        requestId: row.request_id,
        status: input.decision,
        expiresAt: row.expires_at,
        identity,
        scope: JSON.parse(row.scope_json) as PermissionScope,
      };
    });
  }

  decideApprovalByRequestId(input: {
    requestId: string;
    decision: "approved" | "denied";
    now: string;
  }): ApprovalRecord {
    return this.transaction(() => {
      const row = this.#database
        .prepare(
          `SELECT request_id, status, expires_at, identity_json, scope_json
           FROM approvals WHERE request_id = ?`,
        )
        .get(input.requestId) as ApprovalRow | undefined;
      if (row === undefined) {
        throw new GatewayError({
          code: gatewayErrorCodes.approvalNotFound,
          message: "Approval request was not found.",
          status: 404,
        });
      }
      if (new Date(row.expires_at).getTime() <= new Date(input.now).getTime()) {
        throw new GatewayError({
          code: gatewayErrorCodes.approvalExpired,
          message: "Approval request has expired.",
          status: 410,
        });
      }
      if (row.status !== "pending") {
        throw new GatewayError({
          code: gatewayErrorCodes.approvalReplayed,
          message: "Approval request has already been decided.",
          status: 409,
        });
      }
      this.#database
        .prepare(
          `UPDATE approvals SET status = ?, decided_at = ?
           WHERE request_id = ? AND status = 'pending'`,
        )
        .run(input.decision, input.now, input.requestId);
      return {
        requestId: row.request_id,
        status: input.decision,
        expiresAt: row.expires_at,
        identity: JSON.parse(row.identity_json) as RemoteIdentity,
        scope: JSON.parse(row.scope_json) as PermissionScope,
      };
    });
  }

  consumeApproval(
    requestId: string,
    sessionId: string,
    now: string,
  ): ApprovalRecord | undefined {
    return this.transaction(() => {
      const row = this.#database
        .prepare(
          `SELECT request_id, status, expires_at, identity_json, scope_json
           FROM approvals WHERE request_id = ?`,
        )
        .get(requestId) as ApprovalRow | undefined;
      if (row === undefined) {
        return undefined;
      }
      const identity = JSON.parse(row.identity_json) as RemoteIdentity;
      if (identity.sessionId !== sessionId) {
        throw new GatewayError({
          code: gatewayErrorCodes.approvalMismatch,
          message: "Approval request belongs to a different Copilot session.",
          status: 403,
        });
      }
      let status = row.status;
      if (
        status === "pending" &&
        new Date(row.expires_at).getTime() <= new Date(now).getTime()
      ) {
        status = "denied";
        this.#database
          .prepare(
            `UPDATE approvals SET status = 'denied', decided_at = ?
             WHERE request_id = ? AND status = 'pending'`,
          )
          .run(now, requestId);
      } else if (status === "approved" || status === "denied") {
        this.#database
          .prepare(
            `UPDATE approvals SET status = 'consumed', consumed_at = ?
             WHERE request_id = ? AND status = ?`,
          )
          .run(now, requestId, status);
      }
      return {
        requestId,
        status,
        expiresAt: row.expires_at,
        identity,
        scope: JSON.parse(row.scope_json) as PermissionScope,
      };
    });
  }

  listPendingApprovals(now: string): ApprovalRecord[] {
    const rows = this.#database
      .prepare(
        `SELECT request_id, status, expires_at, identity_json, scope_json
         FROM approvals
         WHERE status = 'pending' AND expires_at > ?
         ORDER BY created_at`,
      )
      .all(now) as unknown as ApprovalRow[];
    return rows.map((row) => ({
      requestId: row.request_id,
      status: row.status,
      expiresAt: row.expires_at,
      identity: JSON.parse(row.identity_json) as RemoteIdentity,
      scope: JSON.parse(row.scope_json) as PermissionScope,
    }));
  }

  appendAudit(input: {
    createdAt: string;
    eventType: string;
    actor: string;
    routeKey?: string;
    details?: Readonly<Record<string, unknown>>;
  }): void {
    this.#database
      .prepare(
        `INSERT INTO audit_events
          (created_at, event_type, actor, route_key, details_json)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        input.createdAt,
        input.eventType,
        input.actor,
        input.routeKey ?? null,
        JSON.stringify(input.details ?? {}),
      );
  }

  listAudit(limit = 100): AuditEvent[] {
    const rows = this.#database
      .prepare(
        `SELECT id, created_at, event_type, actor, route_key, details_json
         FROM audit_events ORDER BY id DESC LIMIT ?`,
      )
      .all(limit) as Array<{
      id: number;
      created_at: string;
      event_type: string;
      actor: string;
      route_key: string | null;
      details_json: string;
    }>;
    return rows.map((row) => ({
      id: row.id,
      createdAt: row.created_at,
      eventType: row.event_type,
      actor: row.actor,
      ...(row.route_key === null ? {} : { routeKey: row.route_key }),
      details: JSON.parse(row.details_json) as Readonly<
        Record<string, unknown>
      >,
    }));
  }

  setChannelState(
    channelId: string,
    key: string,
    value: unknown,
    now: string,
  ): void {
    this.#database
      .prepare(
        `INSERT INTO channel_state (channel_id, state_key, value_json, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(channel_id, state_key) DO UPDATE SET
          value_json = excluded.value_json,
          updated_at = excluded.updated_at`,
      )
      .run(channelId, key, JSON.stringify(value), now);
  }

  getChannelState<T>(channelId: string, key: string): T | undefined {
    const row = this.#database
      .prepare(
        `SELECT value_json FROM channel_state
         WHERE channel_id = ? AND state_key = ?`,
      )
      .get(channelId, key) as { value_json: string } | undefined;
    return row === undefined ? undefined : (JSON.parse(row.value_json) as T);
  }
}
