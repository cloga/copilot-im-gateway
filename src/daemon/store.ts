import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type {
  ChannelAccountIdentity,
  ImInboundMessage,
  MinimalInboundEnvelope,
  RouteIdentity,
  RouteKey,
  SessionBinding,
  TenantId,
} from "../core/contracts.js";
import {
  canonicalizeIdentityComponents,
  localTenantId,
  toRouteKey,
} from "../core/contracts.js";
import { GatewayError, gatewayErrorCodes } from "../core/errors.js";
import type {
  Clock,
  PermissionScope,
  RemoteIdentity,
} from "../core/security.js";
import {
  canonicalizeWorkspace,
  digestApprovalOperation,
  digestPermissionScope,
  hashSecret,
  systemClock,
} from "../core/security.js";

const schemaVersion = 2;

interface CountRow {
  count: number;
}

interface ApprovalRow {
  request_id: string;
  status: ApprovalRecord["status"];
  expires_at: string;
  identity_json: string;
  scope_json: string;
  operation_digest: string;
}

interface InboundRow {
  id: number;
  route_key: string;
  tenant_id: string;
  channel_id: string;
  account_id: string;
  conversation_id: string;
  sender_id: string;
  message_id: string;
  received_at: string;
  text: string;
  attachments_json: string;
  reply_to_message_id: string | null;
  workspace_alias: string;
  route_sequence: number;
}

export interface GatewayStoreOptions {
  clock?: Clock;
  ownerId?: string;
  ownershipLeaseMs?: number;
  reservationLeaseMs?: number;
  rateLimit?: number;
  rateWindowMs?: number;
  maxPendingGlobal?: number;
  maxPendingPerRoute?: number;
  maxAttempts?: number;
  retryBaseMs?: number;
  retryMaxMs?: number;
  inboxRetentionDays?: number;
  auditRetentionDays?: number;
}

interface RequiredStoreOptions {
  ownershipLeaseMs: number;
  reservationLeaseMs: number;
  rateLimit: number;
  rateWindowMs: number;
  maxPendingGlobal: number;
  maxPendingPerRoute: number;
  maxAttempts: number;
  retryBaseMs: number;
  retryMaxMs: number;
  inboxRetentionDays: number;
  auditRetentionDays: number;
}

export type AdmissionDisposition =
  | "reserved"
  | "accepted"
  | "control"
  | "denied"
  | "route_denied"
  | "rate_limited"
  | "capacity_rejected"
  | "materialization_failed";

export interface AdmissionResult {
  disposition: AdmissionDisposition | "duplicate";
  routeKey: RouteKey;
  reservationId?: string;
  routeSequence?: number;
  previousDisposition?: AdmissionDisposition;
}

export interface LeasedInboundMessage {
  id: number;
  leaseId: string;
  routeKey: RouteKey;
  routeSequence: number;
  message: ImInboundMessage;
  workspaceAlias: string;
}

export interface ApprovalRecord {
  requestId: string;
  status: "pending" | "approved" | "denied" | "consumed";
  expiresAt: string;
  identity: RemoteIdentity;
  scope: PermissionScope;
  operationDigest: string;
}

export interface AuditEvent {
  id: number;
  createdAt: string;
  eventType: string;
  actor: string;
  routeKey?: string;
  details: Readonly<Record<string, unknown>>;
}

const terminalStatuses = ["completed", "failed", "control"] as const;

export class GatewayStore {
  readonly #database: DatabaseSync;
  readonly #clock: Clock;
  readonly #ownerToken: string;
  readonly #ownerId: string;
  readonly #options: RequiredStoreOptions;
  #closed = false;

  constructor(databasePath: string, options: GatewayStoreOptions = {}) {
    mkdirSync(path.dirname(databasePath), { recursive: true });
    this.#database = new DatabaseSync(databasePath);
    this.#clock = options.clock ?? systemClock;
    this.#ownerToken = randomUUID();
    this.#ownerId = options.ownerId ?? `gateway-${process.pid}`;
    this.#options = {
      ownershipLeaseMs: options.ownershipLeaseMs ?? 15_000,
      reservationLeaseMs: options.reservationLeaseMs ?? 30_000,
      rateLimit: options.rateLimit ?? 12,
      rateWindowMs: options.rateWindowMs ?? 60_000,
      maxPendingGlobal: options.maxPendingGlobal ?? 1_000,
      maxPendingPerRoute: options.maxPendingPerRoute ?? 100,
      maxAttempts: options.maxAttempts ?? 3,
      retryBaseMs: options.retryBaseMs ?? 1_000,
      retryMaxMs: options.retryMaxMs ?? 30_000,
      inboxRetentionDays: options.inboxRetentionDays ?? 14,
      auditRetentionDays: options.auditRetentionDays ?? 30,
    };
    try {
      this.#database.exec(
        "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 2500;",
      );
      this.#migrate();
      this.#acquireOwnership();
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  close(): void {
    if (this.#closed) {
      return;
    }
    this.#runImmediate(() => {
      this.#database
        .prepare(
          "DELETE FROM gateway_ownership WHERE singleton = 1 AND owner_token = ?",
        )
        .run(this.#ownerToken);
    }, false);
    this.#database.close();
    this.#closed = true;
  }

  renewOwnership(): void {
    this.#runImmediate(() => {
      const now = this.#clock.now();
      const result = this.#database
        .prepare(
          `UPDATE gateway_ownership
           SET expires_at = ?, renewed_at = ?
           WHERE singleton = 1 AND owner_token = ? AND expires_at > ?`,
        )
        .run(
          new Date(now.getTime() + this.#options.ownershipLeaseMs).toISOString(),
          now.toISOString(),
          this.#ownerToken,
          now.toISOString(),
        );
      if (result.changes !== 1) {
        throw this.#ownershipError();
      }
    }, false);
  }

  transaction<T>(operation: () => T): T {
    return this.#runImmediate(operation, true);
  }

  #runImmediate<T>(operation: () => T, requireOwnership: boolean): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      if (requireOwnership) {
        this.#assertOwnership();
      }
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      this.#database.exec("ROLLBACK");
      throw error;
    }
  }

  #assertOwnership(): void {
    const row = this.#database
      .prepare(
        `SELECT owner_token, expires_at FROM gateway_ownership
         WHERE singleton = 1`,
      )
      .get() as { owner_token: string; expires_at: string } | undefined;
    if (
      row?.owner_token !== this.#ownerToken ||
      row.expires_at <= this.#clock.now().toISOString()
    ) {
      throw this.#ownershipError();
    }
  }

  #ownershipError(): GatewayError {
    return new GatewayError({
      code: gatewayErrorCodes.ownershipConflict,
      message: "Another gateway process owns this SQLite database.",
      status: 409,
      retryable: true,
    });
  }

  #localTenant(value: string): TenantId {
    if (value !== localTenantId) {
      throw new GatewayError({
        code: gatewayErrorCodes.migrationRequired,
        message: "Stored route has an unsupported tenant identity.",
        status: 409,
      });
    }
    return localTenantId;
  }

  #acquireOwnership(): void {
    this.#runImmediate(() => {
      const now = this.#clock.now();
      const current = this.#database
        .prepare(
          `SELECT owner_token, owner_id, expires_at
           FROM gateway_ownership WHERE singleton = 1`,
        )
        .get() as
        | { owner_token: string; owner_id: string; expires_at: string }
        | undefined;
      if (
        current !== undefined &&
        current.owner_token !== this.#ownerToken &&
        current.expires_at > now.toISOString()
      ) {
        throw this.#ownershipError();
      }
      this.#database
        .prepare(
          `INSERT INTO gateway_ownership
             (singleton, owner_token, owner_id, expires_at, renewed_at)
           VALUES (1, ?, ?, ?, ?)
           ON CONFLICT(singleton) DO UPDATE SET
             owner_token = excluded.owner_token,
             owner_id = excluded.owner_id,
             expires_at = excluded.expires_at,
             renewed_at = excluded.renewed_at`,
        )
        .run(
          this.#ownerToken,
          this.#ownerId,
          new Date(now.getTime() + this.#options.ownershipLeaseMs).toISOString(),
          now.toISOString(),
        );
    }, false);
  }

  #migrate(): void {
    this.#runImmediate(() => {
      const version = (
        this.#database.prepare("PRAGMA user_version").get() as {
          user_version: number;
        }
      ).user_version;
      if (version > schemaVersion) {
        throw new GatewayError({
          code: gatewayErrorCodes.migrationRequired,
          message: "Gateway database schema is newer than this runtime.",
          status: 409,
        });
      }
      if (version === schemaVersion) {
        return;
      }

      const hasLegacy = this.#tableExists("inbound_messages");
      if (hasLegacy && !this.#columnExists("inbound_messages", "route_key")) {
        for (const table of [
          "workspace_aliases",
          "allowed_senders",
          "session_bindings",
          "inbound_messages",
          "approvals",
          "audit_events",
          "channel_state",
        ]) {
          if (this.#tableExists(table)) {
            this.#database.exec(
              `ALTER TABLE ${table} RENAME TO legacy_v1_${table}`,
            );
          }
        }
      }

      this.#createSchema();
      if (this.#tableExists("legacy_v1_workspace_aliases")) {
        this.#database.exec(
          `INSERT OR IGNORE INTO workspace_aliases
             (alias, canonical_path, classification, created_at, updated_at)
           SELECT alias, canonical_path, classification, created_at, updated_at
           FROM legacy_v1_workspace_aliases`,
        );
        this.#quarantineLegacyTables();
      }
      this.#database.exec(`PRAGMA user_version = ${schemaVersion}`);
    }, false);
  }

  #tableExists(name: string): boolean {
    return (
      this.#database
        .prepare(
          "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?",
        )
        .get(name) !== undefined
    );
  }

  #columnExists(table: string, column: string): boolean {
    const rows = this.#database.prepare(`PRAGMA table_info(${table})`).all() as Array<{
      name: string;
    }>;
    return rows.some((row) => row.name === column);
  }

  #createSchema(): void {
    this.#database.exec(`
      CREATE TABLE IF NOT EXISTS workspace_aliases (
        alias TEXT PRIMARY KEY,
        canonical_path TEXT NOT NULL,
        classification TEXT NOT NULL CHECK (classification IN ('personal', 'work')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS allowed_senders (
        tenant_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        display_name TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, channel_id, account_id, sender_id)
      );
      CREATE TABLE IF NOT EXISTS session_bindings (
        route_key TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        workspace_alias TEXT NOT NULL REFERENCES workspace_aliases(alias),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS route_sequences (
        route_key TEXT PRIMARY KEY,
        next_sequence INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS inbound_admissions (
        route_key TEXT NOT NULL,
        message_id_hash TEXT NOT NULL,
        disposition TEXT NOT NULL CHECK (disposition IN
          ('reserved','accepted','control','denied','route_denied','rate_limited',
           'capacity_rejected','materialization_failed')),
        reservation_id TEXT,
        reservation_expires_at TEXT,
        route_sequence INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (route_key, message_id_hash)
      );
      CREATE TABLE IF NOT EXISTS inbound_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        route_key TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        route_sequence INTEGER NOT NULL,
        received_at TEXT NOT NULL,
        text TEXT NOT NULL,
        attachments_json TEXT NOT NULL,
        reply_to_message_id TEXT,
        status TEXT NOT NULL CHECK (status IN
          ('pending','leased','retry_wait','completed','failed','control')),
        attempt_count INTEGER NOT NULL DEFAULT 0,
        available_at TEXT NOT NULL,
        lease_id TEXT,
        lease_expires_at TEXT,
        error_code TEXT,
        created_at TEXT NOT NULL,
        terminal_at TEXT,
        UNIQUE (route_key, message_id),
        UNIQUE (route_key, route_sequence)
      );
      CREATE INDEX IF NOT EXISTS idx_inbound_ready
        ON inbound_messages(status, available_at, route_key, route_sequence);
      CREATE TABLE IF NOT EXISTS rate_events (
        sender_key TEXT NOT NULL,
        occurred_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_rate_events
        ON rate_events(sender_key, occurred_at);
      CREATE TABLE IF NOT EXISTS approvals (
        request_id TEXT PRIMARY KEY,
        nonce_hash TEXT NOT NULL UNIQUE,
        identity_json TEXT NOT NULL,
        identity_digest TEXT NOT NULL,
        scope_json TEXT NOT NULL,
        scope_digest TEXT NOT NULL,
        operation_digest TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','consumed')),
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
        tenant_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        state_key TEXT NOT NULL,
        value_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, channel_id, account_id, state_key)
      );
      CREATE TABLE IF NOT EXISTS active_channel_accounts (
        tenant_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, channel_id)
      );
      CREATE TABLE IF NOT EXISTS legacy_quarantine (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        source_count INTEGER NOT NULL,
        reason TEXT NOT NULL,
        quarantined_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS gateway_ownership (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        owner_token TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        renewed_at TEXT NOT NULL
      );
    `);
  }

  #quarantineLegacyTables(): void {
    const now = this.#clock.now().toISOString();
    const quarantined: Array<{ entity: string; table: string }> = [
      { entity: "allowed_senders", table: "legacy_v1_allowed_senders" },
      { entity: "session_bindings", table: "legacy_v1_session_bindings" },
      { entity: "inbound_messages", table: "legacy_v1_inbound_messages" },
      { entity: "approvals", table: "legacy_v1_approvals" },
      { entity: "audit_events", table: "legacy_v1_audit_events" },
      { entity: "channel_state", table: "legacy_v1_channel_state" },
    ];
    const counts: Record<string, number> = {};
    for (const candidate of quarantined) {
      if (!this.#tableExists(candidate.table)) {
        continue;
      }
      const count = (
        this.#database
          .prepare(`SELECT COUNT(*) AS count FROM ${candidate.table}`)
          .get() as unknown as CountRow
      ).count;
      counts[candidate.entity] = count;
      this.#database
        .prepare(
          `INSERT INTO legacy_quarantine
             (entity_type, source_count, reason, quarantined_at)
           VALUES (?, ?, ?, ?)`,
        )
        .run(
          candidate.entity,
          count,
          "Missing tenant/account identity; retained in legacy_v1 table and excluded from runtime.",
          now,
        );
    }
    this.#insertAudit({
      createdAt: now,
      eventType: "migration.v1.quarantined",
      actor: "system:migration",
      details: counts,
    });
  }

  upsertWorkspaceAlias(
    alias: string,
    workspacePath: string,
    classification: "personal" | "work",
    now: string,
  ): void {
    this.transaction(() => {
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
        .run(
          alias,
          canonicalizeWorkspace(workspacePath),
          classification,
          now,
          now,
        );
      this.#insertAudit({
        createdAt: now,
        eventType: "workspace.alias.updated",
        actor: "local-admin",
        details: { alias, classification },
      });
    });
  }

  getWorkspaceAlias(alias: string):
    | { alias: string; path: string; classification: "personal" | "work" }
    | undefined {
    return this.#database
      .prepare(
        `SELECT alias, canonical_path AS path, classification
         FROM workspace_aliases WHERE alias = ?`,
      )
      .get(alias) as
      | { alias: string; path: string; classification: "personal" | "work" }
      | undefined;
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
    identity: Omit<RouteIdentity, "conversationId">,
    displayName: string | undefined,
    now: string,
  ): void {
    this.transaction(() => {
      this.#database
        .prepare(
          `INSERT INTO allowed_senders
             (tenant_id, channel_id, account_id, sender_id, display_name, created_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(tenant_id, channel_id, account_id, sender_id)
           DO UPDATE SET display_name = excluded.display_name`,
        )
        .run(
          identity.tenantId,
          identity.channelId,
          identity.accountId,
          identity.senderId,
          displayName ?? null,
          now,
        );
      this.#insertAudit({
        createdAt: now,
        eventType: "sender.allowed",
        actor: "local-admin",
        details: {
          tenantId: identity.tenantId,
          channelId: identity.channelId,
          accountId: identity.accountId,
          senderId: identity.senderId,
        },
      });
    });
  }

  isSenderAllowed(identity: RouteIdentity): boolean {
    return (
      (
        this.#database
          .prepare(
            `SELECT COUNT(*) AS count FROM allowed_senders
             WHERE tenant_id = ? AND channel_id = ? AND account_id = ?
               AND sender_id = ?`,
          )
          .get(
            identity.tenantId,
            identity.channelId,
            identity.accountId,
            identity.senderId,
          ) as unknown as CountRow
      ).count > 0
    );
  }

  listAllowedSenders(): Array<{
    tenantId: string;
    channelId: string;
    accountId: string;
    senderId: string;
    displayName?: string;
  }> {
    const rows = this.#database
      .prepare(
        `SELECT tenant_id, channel_id, account_id, sender_id, display_name
         FROM allowed_senders
         ORDER BY tenant_id, channel_id, account_id, sender_id`,
      )
      .all() as Array<{
      tenant_id: string;
      channel_id: string;
      account_id: string;
      sender_id: string;
      display_name: string | null;
    }>;
    return rows.map((row) => ({
      tenantId: this.#localTenant(row.tenant_id),
      channelId: row.channel_id,
      accountId: row.account_id,
      senderId: row.sender_id,
      ...(row.display_name === null ? {} : { displayName: row.display_name }),
    }));
  }

  upsertBinding(
    binding: Omit<SessionBinding, "routeKey" | "createdAt" | "updatedAt">,
    now: string,
  ): SessionBinding {
    return this.transaction(() => {
      const routeKey = toRouteKey(binding);
      this.#database
        .prepare(
          `INSERT INTO session_bindings
             (route_key, tenant_id, channel_id, account_id, conversation_id,
              sender_id, session_id, workspace_alias, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(route_key) DO UPDATE SET
             session_id = excluded.session_id,
             workspace_alias = excluded.workspace_alias,
             updated_at = excluded.updated_at`,
        )
        .run(
          routeKey,
          binding.tenantId,
          binding.channelId,
          binding.accountId,
          binding.conversationId,
          binding.senderId,
          binding.sessionId,
          binding.workspaceAlias,
          now,
          now,
        );
      const result = this.#getBinding(routeKey);
      if (result === undefined) {
        throw new GatewayError({
          code: gatewayErrorCodes.internal,
          message: "Binding could not be read after update.",
          status: 500,
        });
      }
      this.#insertAudit({
        createdAt: now,
        eventType: "session.binding.updated",
        actor: "local-admin",
        routeKey,
        details: {
          sessionId: binding.sessionId,
          workspaceAlias: binding.workspaceAlias,
        },
      });
      return result;
    });
  }

  getBinding(identity: RouteIdentity): SessionBinding | undefined {
    return this.#getBinding(toRouteKey(identity));
  }

  #getBinding(routeKey: RouteKey): SessionBinding | undefined {
    const row = this.#database
      .prepare(
        `SELECT route_key, tenant_id, channel_id, account_id, conversation_id,
                sender_id, session_id, workspace_alias, created_at, updated_at
         FROM session_bindings WHERE route_key = ?`,
      )
      .get(routeKey) as
      | {
          route_key: string;
          tenant_id: string;
          channel_id: string;
          account_id: string;
          conversation_id: string;
          sender_id: string;
          session_id: string;
          workspace_alias: string;
          created_at: string;
          updated_at: string;
        }
      | undefined;
    return row === undefined
      ? undefined
      : {
          routeKey: row.route_key as RouteKey,
          tenantId: this.#localTenant(row.tenant_id),
          channelId: row.channel_id,
          accountId: row.account_id,
          conversationId: row.conversation_id,
          senderId: row.sender_id,
          sessionId: row.session_id,
          workspaceAlias: row.workspace_alias,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        };
  }

  listBindings(): SessionBinding[] {
    const rows = this.#database
      .prepare(
        `SELECT route_key, tenant_id, channel_id, account_id, conversation_id,
                sender_id, session_id, workspace_alias, created_at, updated_at
         FROM session_bindings ORDER BY route_key`,
      )
      .all() as Array<{
      route_key: string;
      tenant_id: string;
      channel_id: string;
      account_id: string;
      conversation_id: string;
      sender_id: string;
      session_id: string;
      workspace_alias: string;
      created_at: string;
      updated_at: string;
    }>;
    return rows.map((row) => ({
      routeKey: row.route_key as RouteKey,
      tenantId: this.#localTenant(row.tenant_id),
      channelId: row.channel_id,
      accountId: row.account_id,
      conversationId: row.conversation_id,
      senderId: row.sender_id,
      sessionId: row.session_id,
      workspaceAlias: row.workspace_alias,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  reserveInbound(
    envelope: Pick<MinimalInboundEnvelope, "identity" | "messageId">,
    now: string,
  ): AdmissionResult {
    return this.transaction(() => {
      const routeKey = toRouteKey(envelope.identity);
      const messageIdHash = hashSecret(envelope.messageId, "message-id");
      const existing = this.#database
        .prepare(
          `SELECT disposition, reservation_id, reservation_expires_at,
                  route_sequence
           FROM inbound_admissions
           WHERE route_key = ? AND message_id_hash = ?`,
        )
        .get(routeKey, messageIdHash) as
        | {
            disposition: AdmissionDisposition;
            reservation_id: string | null;
            reservation_expires_at: string | null;
            route_sequence: number | null;
          }
        | undefined;
      if (existing !== undefined) {
        if (
          existing.disposition === "reserved" &&
          existing.reservation_expires_at !== null &&
          existing.reservation_expires_at <= now
        ) {
          const reservationId = randomUUID();
          this.#database
            .prepare(
              `UPDATE inbound_admissions
               SET reservation_id = ?, reservation_expires_at = ?, updated_at = ?
               WHERE route_key = ? AND message_id_hash = ?`,
            )
            .run(
              reservationId,
              new Date(
                new Date(now).getTime() + this.#options.reservationLeaseMs,
              ).toISOString(),
              now,
              routeKey,
              messageIdHash,
            );
          return {
            disposition: "reserved",
            routeKey,
            reservationId,
            ...(existing.route_sequence === null
              ? {}
              : { routeSequence: existing.route_sequence }),
          };
        }
        return {
          disposition: "duplicate",
          routeKey,
          previousDisposition: existing.disposition,
        };
      }

      if (!this.isSenderAllowed(envelope.identity)) {
        this.#insertAdmission(
          routeKey,
          messageIdHash,
          "denied",
          null,
          null,
          null,
          now,
        );
        this.#insertAudit({
          createdAt: now,
          eventType: "inbound.sender.denied",
          actor: `sender-hash:${hashSecret(envelope.identity.senderId, "sender-id")}`,
          routeKey,
          details: {
            tenantHash: hashSecret(envelope.identity.tenantId, "tenant-id"),
            channelHash: hashSecret(envelope.identity.channelId, "channel-id"),
            accountHash: hashSecret(envelope.identity.accountId, "account-id"),
            conversationHash: hashSecret(
              envelope.identity.conversationId,
              "conversation-id",
            ),
            messageHash: messageIdHash,
          },
        });
        return { disposition: "denied", routeKey };
      }

      const authorizedBinding = this.#database
        .prepare(
          `SELECT 1 AS present
           FROM session_bindings b
           JOIN workspace_aliases w ON w.alias = b.workspace_alias
           WHERE b.route_key = ? AND w.classification = 'personal'`,
        )
        .get(routeKey);
      if (authorizedBinding === undefined) {
        this.#insertAdmission(
          routeKey,
          messageIdHash,
          "route_denied",
          null,
          null,
          null,
          now,
        );
        this.#insertAudit({
          createdAt: now,
          eventType: "inbound.route.denied",
          actor: `sender-hash:${hashSecret(envelope.identity.senderId, "sender-id")}`,
          routeKey,
          details: { messageHash: messageIdHash },
        });
        return { disposition: "route_denied", routeKey };
      }

      const senderKey = hashSecret(
        canonicalizeIdentityComponents([
          envelope.identity.tenantId,
          envelope.identity.channelId,
          envelope.identity.accountId,
          envelope.identity.senderId,
        ]),
        "rate-limit-sender",
      );
      const cutoff = new Date(
        new Date(now).getTime() - this.#options.rateWindowMs,
      ).toISOString();
      this.#database
        .prepare("DELETE FROM rate_events WHERE occurred_at <= ?")
        .run(cutoff);
      const rateCount = (
        this.#database
          .prepare(
            `SELECT COUNT(*) AS count FROM rate_events
             WHERE sender_key = ? AND occurred_at > ?`,
          )
          .get(senderKey, cutoff) as unknown as CountRow
      ).count;
      if (rateCount >= this.#options.rateLimit) {
        this.#insertAdmission(
          routeKey,
          messageIdHash,
          "rate_limited",
          null,
          null,
          null,
          now,
        );
        this.#insertAudit({
          createdAt: now,
          eventType: "inbound.rate_limited",
          actor: `sender-hash:${hashSecret(envelope.identity.senderId, "sender-id")}`,
          routeKey,
          details: { messageHash: messageIdHash },
        });
        return { disposition: "rate_limited", routeKey };
      }

      const globalPending = this.#pendingCount(now);
      const routePending = this.#pendingCount(now, routeKey);
      if (
        globalPending >= this.#options.maxPendingGlobal ||
        routePending >= this.#options.maxPendingPerRoute
      ) {
        this.#insertAdmission(
          routeKey,
          messageIdHash,
          "capacity_rejected",
          null,
          null,
          null,
          now,
        );
        this.#insertAudit({
          createdAt: now,
          eventType: "inbound.capacity_rejected",
          actor: "system:admission",
          routeKey,
          details: { globalPending, routePending },
        });
        return { disposition: "capacity_rejected", routeKey };
      }

      this.#database
        .prepare("INSERT INTO rate_events (sender_key, occurred_at) VALUES (?, ?)")
        .run(senderKey, now);
      const reservationId = randomUUID();
      const routeSequence = this.#nextSequence(routeKey);
      this.#insertAdmission(
        routeKey,
        messageIdHash,
        "reserved",
        reservationId,
        new Date(
          new Date(now).getTime() + this.#options.reservationLeaseMs,
        ).toISOString(),
        routeSequence,
        now,
      );
      return { disposition: "reserved", routeKey, reservationId, routeSequence };
    });
  }

  #pendingCount(now: string, routeKey?: RouteKey): number {
    const messageQuery =
      routeKey === undefined
        ? `SELECT COUNT(*) AS count FROM inbound_messages
           WHERE status IN ('pending','leased','retry_wait')`
        : `SELECT COUNT(*) AS count FROM inbound_messages
           WHERE route_key = ? AND status IN ('pending','leased','retry_wait')`;
    const reservationQuery =
      routeKey === undefined
        ? `SELECT COUNT(*) AS count FROM inbound_admissions
           WHERE disposition = 'reserved' AND reservation_expires_at > ?`
        : `SELECT COUNT(*) AS count FROM inbound_admissions
           WHERE route_key = ? AND disposition = 'reserved'
             AND reservation_expires_at > ?`;
    const messages = (
      (routeKey === undefined
        ? this.#database.prepare(messageQuery).get()
        : this.#database.prepare(messageQuery).get(routeKey)) as unknown as CountRow
    ).count;
    const reservations = (
      (routeKey === undefined
        ? this.#database.prepare(reservationQuery).get(now)
        : this.#database
            .prepare(reservationQuery)
            .get(routeKey, now)) as unknown as CountRow
    ).count;
    return messages + reservations;
  }

  #insertAdmission(
    routeKey: RouteKey,
    messageIdHash: string,
    disposition: AdmissionDisposition,
    reservationId: string | null,
    reservationExpiresAt: string | null,
    routeSequence: number | null,
    now: string,
  ): void {
    this.#database
      .prepare(
        `INSERT INTO inbound_admissions
           (route_key, message_id_hash, disposition, reservation_id,
            reservation_expires_at, route_sequence, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        routeKey,
        messageIdHash,
        disposition,
        reservationId,
        reservationExpiresAt,
        routeSequence,
        now,
        now,
      );
  }

  finalizeInbound(
    reservation: AdmissionResult,
    message: ImInboundMessage,
    now: string,
  ): boolean {
    return this.transaction(() => {
      this.#validateReservation(reservation, message, now);
      const sequence = reservation.routeSequence;
      if (sequence === undefined) {
        throw new GatewayError({
          code: gatewayErrorCodes.conflict,
          message: "Inbound reservation has no durable route sequence.",
          status: 409,
        });
      }
      const result = this.#database
        .prepare(
          `INSERT OR IGNORE INTO inbound_messages
             (route_key, tenant_id, channel_id, account_id, conversation_id,
              sender_id, message_id, route_sequence, received_at, text,
              attachments_json, reply_to_message_id, status, available_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
        )
        .run(
          reservation.routeKey,
          message.tenantId,
          message.channelId,
          message.accountId,
          message.conversationId,
          message.senderId,
          message.messageId,
          sequence,
          message.receivedAt,
          message.text,
          JSON.stringify(message.attachments),
          message.replyToMessageId ?? null,
          now,
          now,
        );
      this.#finishAdmission(
        reservation,
        message.messageId,
        result.changes === 1 ? "accepted" : "materialization_failed",
        now,
      );
      this.#insertAudit({
        createdAt: now,
        eventType:
          result.changes === 1 ? "inbound.accepted" : "inbound.duplicate",
        actor: `sender-hash:${hashSecret(message.senderId, "sender-id")}`,
        routeKey: reservation.routeKey,
        details: {
          messageHash: hashSecret(message.messageId, "message-id"),
          sequence,
        },
      });
      return result.changes === 1;
    });
  }

  failMaterialization(
    reservation: AdmissionResult,
    messageId: string,
    now: string,
  ): void {
    this.transaction(() => {
      this.#finishAdmission(
        reservation,
        messageId,
        "materialization_failed",
        now,
      );
      this.#insertAudit({
        createdAt: now,
        eventType: "inbound.materialization_failed",
        actor: "system:admission",
        routeKey: reservation.routeKey,
      });
    });
  }

  #validateReservation(
    reservation: AdmissionResult,
    message: ImInboundMessage,
    now: string,
  ): void {
    if (
      reservation.disposition !== "reserved" ||
      reservation.reservationId === undefined ||
      toRouteKey(message) !== reservation.routeKey
    ) {
      throw new GatewayError({
        code: gatewayErrorCodes.conflict,
        message: "Inbound reservation does not match the materialized message.",
        status: 409,
      });
    }
    const row = this.#database
      .prepare(
        `SELECT reservation_id, reservation_expires_at
         FROM inbound_admissions
         WHERE route_key = ? AND message_id_hash = ? AND disposition = 'reserved'`,
      )
      .get(
        reservation.routeKey,
        hashSecret(message.messageId, "message-id"),
      ) as
      | { reservation_id: string; reservation_expires_at: string }
      | undefined;
    if (
      row?.reservation_id !== reservation.reservationId ||
      row.reservation_expires_at <= now
    ) {
      throw new GatewayError({
        code: gatewayErrorCodes.conflict,
        message: "Inbound reservation expired or was replaced.",
        status: 409,
        retryable: true,
      });
    }
  }

  #nextSequence(routeKey: RouteKey): number {
    this.#database
      .prepare(
        `INSERT INTO route_sequences (route_key, next_sequence)
         VALUES (?, 1) ON CONFLICT(route_key) DO NOTHING`,
      )
      .run(routeKey);
    const row = this.#database
      .prepare(
        "SELECT next_sequence FROM route_sequences WHERE route_key = ?",
      )
      .get(routeKey) as { next_sequence: number };
    this.#database
      .prepare(
        "UPDATE route_sequences SET next_sequence = next_sequence + 1 WHERE route_key = ?",
      )
      .run(routeKey);
    return row.next_sequence;
  }

  #finishAdmission(
    reservation: AdmissionResult,
    messageId: string,
    disposition: AdmissionDisposition,
    now: string,
  ): void {
    const result = this.#database
      .prepare(
        `UPDATE inbound_admissions
         SET disposition = ?, reservation_id = NULL,
             reservation_expires_at = NULL, updated_at = ?
         WHERE route_key = ? AND message_id_hash = ?
           AND disposition = 'reserved' AND reservation_id = ?`,
      )
      .run(
        disposition,
        now,
        reservation.routeKey,
        hashSecret(messageId, "message-id"),
        reservation.reservationId ?? null,
      );
    if (result.changes !== 1) {
      throw new GatewayError({
        code: gatewayErrorCodes.conflict,
        message: "Inbound reservation is no longer active.",
        status: 409,
      });
    }
  }

  finalizeApprovalCommand(
    reservation: AdmissionResult,
    message: ImInboundMessage,
    nonce: string,
    decision: "approved" | "denied",
    now: string,
  ): ApprovalRecord {
    return this.transaction(() => {
      this.#validateReservation(reservation, message, now);
      const binding = this.#getBinding(reservation.routeKey);
      if (binding === undefined) {
        throw new GatewayError({
          code: gatewayErrorCodes.notFound,
          message: "Conversation is not bound to a Copilot session.",
          status: 404,
        });
      }
      const identity: RemoteIdentity = {
        tenantId: message.tenantId,
        channelId: message.channelId,
        accountId: message.accountId,
        conversationId: message.conversationId,
        senderId: message.senderId,
        sessionId: binding.sessionId,
      };
      const record = this.#decideApproval(nonce, identity, decision, now);
      const sequence = reservation.routeSequence;
      if (sequence === undefined) {
        throw new GatewayError({
          code: gatewayErrorCodes.conflict,
          message: "Inbound reservation has no durable route sequence.",
          status: 409,
        });
      }
      this.#database
        .prepare(
          `INSERT INTO inbound_messages
             (route_key, tenant_id, channel_id, account_id, conversation_id,
              sender_id, message_id, route_sequence, received_at, text,
              attachments_json, reply_to_message_id, status, available_at,
              created_at, terminal_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', '[]', ?, 'control', ?, ?, ?)`,
        )
        .run(
          reservation.routeKey,
          message.tenantId,
          message.channelId,
          message.accountId,
          message.conversationId,
          message.senderId,
          message.messageId,
          sequence,
          message.receivedAt,
          message.replyToMessageId ?? null,
          now,
          now,
          now,
        );
      this.#finishAdmission(reservation, message.messageId, "control", now);
      this.#insertAudit({
        createdAt: now,
        eventType: `approval.${decision}`,
        actor: `sender-hash:${hashSecret(message.senderId, "sender-id")}`,
        routeKey: reservation.routeKey,
        details: { requestId: record.requestId, sequence },
      });
      return record;
    });
  }

  leaseInbound(
    sessionId: string,
    now: string,
    leaseSeconds: number,
  ): LeasedInboundMessage | undefined {
    return this.transaction(() => {
      this.#recoverExpiredLeases(now);
      const row = this.#database
        .prepare(
          `SELECT m.id, m.route_key, m.tenant_id, m.channel_id, m.account_id,
                  m.conversation_id, m.sender_id, m.message_id, m.route_sequence,
                  m.received_at, m.text, m.attachments_json,
                  m.reply_to_message_id, b.workspace_alias
           FROM inbound_messages m
           JOIN session_bindings b ON b.route_key = m.route_key
           WHERE m.status IN ('pending','retry_wait')
             AND m.available_at <= ?
             AND b.session_id = ?
             AND NOT EXISTS (
               SELECT 1 FROM inbound_messages earlier
               WHERE earlier.route_key = m.route_key
                 AND earlier.route_sequence < m.route_sequence
                 AND earlier.status IN ('pending','leased','retry_wait')
             )
             AND NOT EXISTS (
               SELECT 1 FROM inbound_admissions reserved
               WHERE reserved.route_key = m.route_key
                 AND reserved.route_sequence < m.route_sequence
                 AND reserved.disposition = 'reserved'
             )
           ORDER BY m.created_at, m.id
           LIMIT 1`,
        )
        .get(now, sessionId) as InboundRow | undefined;
      if (row === undefined) {
        return undefined;
      }
      const leaseId = randomUUID();
      const result = this.#database
        .prepare(
          `UPDATE inbound_messages
           SET status = 'leased', lease_id = ?, lease_expires_at = ?,
               attempt_count = attempt_count + 1
           WHERE id = ? AND status IN ('pending','retry_wait')`,
        )
        .run(
          leaseId,
          new Date(new Date(now).getTime() + leaseSeconds * 1000).toISOString(),
          row.id,
        );
      if (result.changes !== 1) {
        return undefined;
      }
      this.#insertAudit({
        createdAt: now,
        eventType: "inbound.leased",
        actor: "copilot-extension",
        routeKey: row.route_key as RouteKey,
        details: { id: row.id, sequence: row.route_sequence },
      });
      return {
        id: row.id,
        leaseId,
        routeKey: row.route_key as RouteKey,
        routeSequence: row.route_sequence,
        workspaceAlias: row.workspace_alias,
        message: {
          tenantId: this.#localTenant(row.tenant_id),
          channelId: row.channel_id,
          accountId: row.account_id,
          conversationId: row.conversation_id,
          senderId: row.sender_id,
          messageId: row.message_id,
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

  #recoverExpiredLeases(now: string): void {
    const rows = this.#database
      .prepare(
        `SELECT id, route_key, attempt_count
         FROM inbound_messages
         WHERE status = 'leased' AND lease_expires_at <= ?`,
      )
      .all(now) as Array<{
      id: number;
      route_key: string;
      attempt_count: number;
    }>;
    for (const row of rows) {
      if (row.attempt_count >= this.#options.maxAttempts) {
        this.#database
          .prepare(
            `UPDATE inbound_messages
             SET status = 'failed', lease_id = NULL, lease_expires_at = NULL,
                 error_code = 'LEASE_RETRY_EXHAUSTED', terminal_at = ?
             WHERE id = ? AND status = 'leased'`,
          )
          .run(now, row.id);
      } else {
        this.#database
          .prepare(
            `UPDATE inbound_messages
             SET status = 'retry_wait', lease_id = NULL, lease_expires_at = NULL,
                 available_at = ?
             WHERE id = ? AND status = 'leased'`,
          )
          .run(this.#retryAt(now, row.attempt_count), row.id);
      }
      this.#insertAudit({
        createdAt: now,
        eventType: "inbound.lease_expired",
        actor: "system:recovery",
        routeKey: row.route_key as RouteKey,
        details: { id: row.id, attempt: row.attempt_count },
      });
    }
  }

  completeInbound(
    id: number,
    leaseId: string,
    outcome: "completed" | "failed",
    errorCode: string | undefined,
    retryable: boolean,
    now: string,
  ): void {
    this.transaction(() => {
      const row = this.#database
        .prepare(
          `SELECT route_key, attempt_count FROM inbound_messages
           WHERE id = ? AND status = 'leased' AND lease_id = ?`,
        )
        .get(id, leaseId) as
        | { route_key: string; attempt_count: number }
        | undefined;
      if (row === undefined) {
        throw new GatewayError({
          code: gatewayErrorCodes.conflict,
          message: "Inbound lease is missing or no longer active.",
          status: 409,
        });
      }
      const shouldRetry =
        outcome === "failed" &&
        retryable &&
        row.attempt_count < this.#options.maxAttempts;
      if (shouldRetry) {
        this.#database
          .prepare(
            `UPDATE inbound_messages
             SET status = 'retry_wait', error_code = ?, available_at = ?,
                 lease_id = NULL, lease_expires_at = NULL
             WHERE id = ? AND lease_id = ?`,
          )
          .run(
            errorCode ?? null,
            this.#retryAt(now, row.attempt_count),
            id,
            leaseId,
          );
      } else {
        this.#database
          .prepare(
            `UPDATE inbound_messages
             SET status = ?, error_code = ?, lease_id = NULL,
                 lease_expires_at = NULL, terminal_at = ?
             WHERE id = ? AND lease_id = ?`,
          )
          .run(outcome, errorCode ?? null, now, id, leaseId);
      }
      this.#insertAudit({
        createdAt: now,
        eventType: shouldRetry ? "inbound.retry_scheduled" : `inbound.${outcome}`,
        actor: "copilot-extension",
        routeKey: row.route_key as RouteKey,
        details: { id, attempt: row.attempt_count },
      });
    });
  }

  #retryAt(now: string, attempt: number): string {
    const delay = Math.min(
      this.#options.retryMaxMs,
      this.#options.retryBaseMs * 2 ** Math.max(0, attempt - 1),
    );
    return new Date(new Date(now).getTime() + delay).toISOString();
  }

  createApproval(input: {
    requestId: string;
    nonce: string;
    identity: RemoteIdentity;
    scope: PermissionScope;
    expiresAt: string;
    now: string;
  }): { operationDigest: string } {
    return this.transaction(() => {
      const scopeDigest = digestPermissionScope(input.scope);
      const operationDigest = digestApprovalOperation(
        input.requestId,
        input.scope,
      );
      this.#database
        .prepare(
          `INSERT INTO approvals
             (request_id, nonce_hash, identity_json, identity_digest, scope_json,
              scope_digest, operation_digest, status, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
        )
        .run(
          input.requestId,
          hashSecret(input.nonce, "approval-nonce"),
          JSON.stringify(input.identity),
          this.#identityDigest(input.identity),
          JSON.stringify(input.scope),
          scopeDigest,
          operationDigest,
          input.expiresAt,
          input.now,
        );
      this.#insertAudit({
        createdAt: input.now,
        eventType: "approval.requested",
        actor: "copilot-extension",
        routeKey: toRouteKey(input.identity),
        details: {
          requestId: input.requestId,
          scopeDigest,
          operationDigest,
          expiresAt: input.expiresAt,
        },
      });
      return { operationDigest };
    });
  }

  decideApproval(input: {
    nonce: string;
    identity: RemoteIdentity;
    decision: "approved" | "denied";
    now: string;
  }): ApprovalRecord {
    return this.transaction(() => {
      const record = this.#decideApproval(
        input.nonce,
        input.identity,
        input.decision,
        input.now,
      );
      this.#insertAudit({
        createdAt: input.now,
        eventType: `approval.${input.decision}`,
        actor: `sender-hash:${hashSecret(input.identity.senderId, "sender-id")}`,
        routeKey: toRouteKey(input.identity),
        details: { requestId: record.requestId },
      });
      return record;
    });
  }

  #decideApproval(
    nonce: string,
    identity: RemoteIdentity,
    decision: "approved" | "denied",
    now: string,
  ): ApprovalRecord {
    const row = this.#database
      .prepare(
        `SELECT request_id, status, expires_at, identity_json, scope_json,
                operation_digest
         FROM approvals WHERE nonce_hash = ?`,
      )
      .get(hashSecret(nonce, "approval-nonce")) as ApprovalRow | undefined;
    if (row === undefined) {
      throw new GatewayError({
        code: gatewayErrorCodes.approvalNotFound,
        message: "Approval nonce was not found.",
        status: 404,
      });
    }
    if (
      this.#identityDigest(identity) !==
      this.#identityDigest(this.#parseIdentity(row.identity_json))
    ) {
      throw new GatewayError({
        code: gatewayErrorCodes.approvalMismatch,
        message: "Approval nonce does not match this remote identity.",
        status: 403,
      });
    }
    this.#validatePendingApproval(row, now);
    this.#database
      .prepare(
        `UPDATE approvals SET status = ?, decided_at = ?
         WHERE request_id = ? AND status = 'pending'`,
      )
      .run(decision, now, row.request_id);
    return this.#approvalRecord(row, decision);
  }

  decideApprovalByRequestId(input: {
    requestId: string;
    decision: "approved" | "denied";
    now: string;
  }): ApprovalRecord {
    return this.transaction(() => {
      const row = this.#getApprovalRow(input.requestId);
      if (row === undefined) {
        throw new GatewayError({
          code: gatewayErrorCodes.approvalNotFound,
          message: "Approval request was not found.",
          status: 404,
        });
      }
      this.#validatePendingApproval(row, input.now);
      this.#database
        .prepare(
          `UPDATE approvals SET status = ?, decided_at = ?
           WHERE request_id = ? AND status = 'pending'`,
        )
        .run(input.decision, input.now, input.requestId);
      const record = this.#approvalRecord(row, input.decision);
      this.#insertAudit({
        createdAt: input.now,
        eventType: `approval.${input.decision}`,
        actor: "local-admin",
        routeKey: toRouteKey(record.identity),
        details: { requestId: record.requestId },
      });
      return record;
    });
  }

  consumeApproval(input: {
    requestId: string;
    identity: RemoteIdentity;
    operationDigest: string;
    now: string;
  }): ApprovalRecord | undefined {
    return this.transaction(() => {
      const row = this.#getApprovalRow(input.requestId);
      if (row === undefined) {
        return undefined;
      }
      if (
        this.#identityDigest(input.identity) !==
          this.#identityDigest(this.#parseIdentity(row.identity_json)) ||
        row.operation_digest !== input.operationDigest
      ) {
        throw new GatewayError({
          code: gatewayErrorCodes.approvalMismatch,
          message: "Approval request identity or operation scope does not match.",
          status: 403,
        });
      }
      let status = row.status;
      if (status !== "consumed" && row.expires_at <= input.now) {
        status = "denied";
        this.#database
          .prepare(
            `UPDATE approvals SET status = 'denied', decided_at = ?
             WHERE request_id = ? AND status != 'consumed'`,
          )
          .run(input.now, input.requestId);
      } else if (status === "approved" || status === "denied") {
        this.#database
          .prepare(
            `UPDATE approvals SET status = 'consumed', consumed_at = ?
             WHERE request_id = ? AND status = ?`,
          )
          .run(input.now, input.requestId, status);
      }
      return this.#approvalRecord(row, status);
    });
  }

  #getApprovalRow(requestId: string): ApprovalRow | undefined {
    return this.#database
      .prepare(
        `SELECT request_id, status, expires_at, identity_json, scope_json,
                operation_digest
         FROM approvals WHERE request_id = ?`,
      )
      .get(requestId) as ApprovalRow | undefined;
  }

  #validatePendingApproval(row: ApprovalRow, now: string): void {
    if (row.expires_at <= now) {
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
  }

  #parseIdentity(value: string): RemoteIdentity {
    const parsed = JSON.parse(value) as Partial<RemoteIdentity>;
    if (
      typeof parsed.tenantId !== "string" ||
      typeof parsed.channelId !== "string" ||
      typeof parsed.accountId !== "string" ||
      typeof parsed.conversationId !== "string" ||
      typeof parsed.senderId !== "string" ||
      typeof parsed.sessionId !== "string"
    ) {
      throw new GatewayError({
        code: gatewayErrorCodes.approvalMismatch,
        message: "Legacy approval identity is incomplete and cannot be used.",
        status: 403,
      });
    }
    return parsed as RemoteIdentity;
  }

  #identityDigest(identity: RemoteIdentity): string {
    return hashSecret(
      canonicalizeIdentityComponents([
        identity.tenantId,
        identity.channelId,
        identity.accountId,
        identity.conversationId,
        identity.senderId,
        identity.sessionId,
      ]),
      "approval-identity",
    );
  }

  #approvalRecord(
    row: ApprovalRow,
    status: ApprovalRecord["status"],
  ): ApprovalRecord {
    return {
      requestId: row.request_id,
      status,
      expiresAt: row.expires_at,
      identity: this.#parseIdentity(row.identity_json),
      scope: JSON.parse(row.scope_json) as PermissionScope,
      operationDigest: row.operation_digest,
    };
  }

  listPendingApprovals(now: string): ApprovalRecord[] {
    const rows = this.#database
      .prepare(
        `SELECT request_id, status, expires_at, identity_json, scope_json,
                operation_digest
         FROM approvals
         WHERE status = 'pending' AND expires_at > ?
         ORDER BY created_at`,
      )
      .all(now) as unknown as ApprovalRow[];
    const records: ApprovalRecord[] = [];
    for (const row of rows) {
      records.push(this.#approvalRecord(row, row.status));
    }
    return records;
  }

  appendAudit(input: {
    createdAt: string;
    eventType: string;
    actor: string;
    routeKey?: string;
    details?: Readonly<Record<string, unknown>>;
  }): void {
    this.transaction(() => this.#insertAudit(input));
  }

  #insertAudit(input: {
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
    identity: ChannelAccountIdentity,
    key: string,
    value: unknown,
    now: string,
  ): void {
    this.transaction(() => {
      this.#database
        .prepare(
          `INSERT INTO channel_state
             (tenant_id, channel_id, account_id, state_key, value_json, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(tenant_id, channel_id, account_id, state_key)
           DO UPDATE SET value_json = excluded.value_json,
                         updated_at = excluded.updated_at`,
        )
        .run(
          identity.tenantId,
          identity.channelId,
          identity.accountId,
          key,
          JSON.stringify(value),
          now,
        );
    });
  }

  getChannelState<T>(
    identity: ChannelAccountIdentity,
    key: string,
  ): T | undefined {
    const row = this.#database
      .prepare(
        `SELECT value_json FROM channel_state
         WHERE tenant_id = ? AND channel_id = ? AND account_id = ?
           AND state_key = ?`,
      )
      .get(
        identity.tenantId,
        identity.channelId,
        identity.accountId,
        key,
      ) as { value_json: string } | undefined;
    return row === undefined ? undefined : (JSON.parse(row.value_json) as T);
  }

  setActiveChannelAccount(
    identity: ChannelAccountIdentity,
    credentials: unknown,
    now: string,
  ): void {
    this.transaction(() => {
      this.#database
        .prepare(
          `INSERT INTO active_channel_accounts
             (tenant_id, channel_id, account_id, updated_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(tenant_id, channel_id)
           DO UPDATE SET account_id = excluded.account_id,
                         updated_at = excluded.updated_at`,
        )
        .run(identity.tenantId, identity.channelId, identity.accountId, now);
      this.#database
        .prepare(
          `INSERT INTO channel_state
             (tenant_id, channel_id, account_id, state_key, value_json, updated_at)
           VALUES (?, ?, ?, 'credentials', ?, ?)
           ON CONFLICT(tenant_id, channel_id, account_id, state_key)
           DO UPDATE SET value_json = excluded.value_json,
                         updated_at = excluded.updated_at`,
        )
        .run(
          identity.tenantId,
          identity.channelId,
          identity.accountId,
          JSON.stringify(credentials),
          now,
        );
    });
  }

  getActiveChannelAccount<T>(
    tenantId: TenantId,
    channelId: string,
  ): { identity: ChannelAccountIdentity; credentials: T } | undefined {
    const row = this.#database
      .prepare(
        `SELECT a.account_id, s.value_json
         FROM active_channel_accounts a
         JOIN channel_state s
           ON s.tenant_id = a.tenant_id
          AND s.channel_id = a.channel_id
          AND s.account_id = a.account_id
          AND s.state_key = 'credentials'
         WHERE a.tenant_id = ? AND a.channel_id = ?`,
      )
      .get(tenantId, channelId) as
      | { account_id: string; value_json: string }
      | undefined;
    return row === undefined
      ? undefined
      : {
          identity: { tenantId, channelId, accountId: row.account_id },
          credentials: JSON.parse(row.value_json) as T,
        };
  }

  cleanup(now: string): { inbox: number; audit: number } {
    return this.transaction(() => {
      const inboxCutoff = new Date(
        new Date(now).getTime() -
          this.#options.inboxRetentionDays * 24 * 60 * 60 * 1000,
      ).toISOString();
      const auditCutoff = new Date(
        new Date(now).getTime() -
          this.#options.auditRetentionDays * 24 * 60 * 60 * 1000,
      ).toISOString();
      const inbox = this.#database
        .prepare(
          `DELETE FROM inbound_messages
           WHERE status IN (${terminalStatuses.map(() => "?").join(",")})
             AND terminal_at < ?`,
        )
        .run(...terminalStatuses, inboxCutoff).changes;
      const audit = this.#database
        .prepare("DELETE FROM audit_events WHERE created_at < ?")
        .run(auditCutoff).changes;
      this.#database
        .prepare(
          `DELETE FROM inbound_admissions
           WHERE updated_at < ? AND disposition <> 'reserved'`,
        )
        .run(inboxCutoff);
      return { inbox: Number(inbox), audit: Number(audit) };
    });
  }
}
