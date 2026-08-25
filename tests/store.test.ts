import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  deferInboundMessage,
  toRouteKey,
  type ImInboundMessage,
  type RouteIdentity,
} from "../src/core/contracts.js";
import type { Clock, PermissionScope } from "../src/core/security.js";
import { GatewayStore, type GatewayStoreOptions } from "../src/daemon/store.js";

const temporaryDirectories: string[] = [];
const start = Date.parse("2026-08-24T00:00:00.000Z");

class MutableClock implements Clock {
  constructor(public timestamp = start) {}
  now(): Date {
    return new Date(this.timestamp);
  }
  advance(milliseconds: number): void {
    this.timestamp += milliseconds;
  }
}

function createDatabasePath(): string {
  const directory = mkdtempSync(path.join(os.tmpdir(), "copilot-im-store-"));
  temporaryDirectories.push(directory);
  return path.join(directory, "gateway.sqlite");
}

function createStore(
  databasePath = createDatabasePath(),
  options: GatewayStoreOptions = {},
): GatewayStore {
  return new GatewayStore(databasePath, options);
}

const identity = (
  accountId = "bot-a",
  conversationId = "conversation",
  senderId = "sender",
): RouteIdentity => ({
  tenantId: "local",
  channelId: "weixin-main",
  accountId,
  conversationId,
  senderId,
});

function message(
  messageId: string,
  route: RouteIdentity = identity(),
  text = "hello",
): ImInboundMessage {
  return {
    ...route,
    messageId,
    receivedAt: new Date(start).toISOString(),
    text,
    attachments: [],
  };
}

function configure(
  store: GatewayStore,
  route: RouteIdentity = identity(),
  sessionId = "session",
): void {
  const now = new Date(start).toISOString();
  store.upsertWorkspaceAlias("personal", "C:\\repo", "personal", now);
  store.allowSender(route, undefined, now);
  store.upsertBinding(
    { ...route, sessionId, workspaceAlias: "personal" },
    now,
  );
}

function admit(
  store: GatewayStore,
  inbound: ImInboundMessage,
  now = inbound.receivedAt,
) {
  const envelope = deferInboundMessage(inbound);
  const reservation = store.reserveInbound(envelope, now);
  if (reservation.disposition === "reserved") {
    store.finalizeInbound(reservation, inbound, now);
  }
  return reservation;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("GatewayStore durable runtime state", () => {
  it("uses collision-safe account-aware routes for binding and idempotency", () => {
    const store = createStore();
    const first = identity("bot-a");
    const second = identity("bot-b");
    configure(store, first, "session-a");
    configure(store, second, "session-b");

    expect(toRouteKey(first)).not.toBe(toRouteKey(second));
    expect(admit(store, message("same-id", first)).disposition).toBe("reserved");
    expect(admit(store, message("same-id", second)).disposition).toBe("reserved");
    expect(store.leaseInbound("session-a", new Date(start).toISOString(), 60)?.message.accountId).toBe(
      "bot-a",
    );
    expect(store.leaseInbound("session-b", new Date(start).toISOString(), 60)?.message.accountId).toBe(
      "bot-b",
    );
    store.close();
  });

  it("persists duplicate and rate-limited dispositions across restart", () => {
    const clock = new MutableClock();
    const databasePath = createDatabasePath();
    let store = createStore(databasePath, { clock, rateLimit: 1 });
    configure(store);
    expect(admit(store, message("first")).disposition).toBe("reserved");
    const limitedEnvelope = deferInboundMessage(message("limited"));
    expect(
      store.reserveInbound(limitedEnvelope, clock.now().toISOString())
        .disposition,
    ).toBe("rate_limited");
    store.close();

    store = createStore(databasePath, { clock, rateLimit: 1 });
    expect(
      store.reserveInbound(limitedEnvelope, clock.now().toISOString()),
    ).toMatchObject({
      disposition: "duplicate",
      previousDisposition: "rate_limited",
    });
    expect(
      store.reserveInbound(
        deferInboundMessage(message("first")),
        clock.now().toISOString(),
      ),
    ).toMatchObject({
      disposition: "duplicate",
      previousDisposition: "accepted",
    });
    store.close();
  });

  it("enforces global and per-route pending capacity", () => {
    const store = createStore(undefined, {
      maxPendingGlobal: 1,
      maxPendingPerRoute: 1,
    });
    configure(store);
    expect(
      store.reserveInbound(
        deferInboundMessage(message("first")),
        new Date(start).toISOString(),
      ).disposition,
    ).toBe("reserved");
    expect(
      store.reserveInbound(
        deferInboundMessage(message("second")),
        new Date(start).toISOString(),
      ).disposition,
    ).toBe("capacity_rejected");
    store.close();
  });

  it("preserves per-route FIFO through retry and restart", () => {
    const clock = new MutableClock();
    const databasePath = createDatabasePath();
    let store = createStore(databasePath, {
      clock,
      retryBaseMs: 1_000,
      rateLimit: 10,
    });

    configure(store);
    admit(store, message("first"));
    admit(store, message("second"));
    const first = store.leaseInbound("session", clock.now().toISOString(), 60);
    expect(first?.message.messageId).toBe("first");
    store.completeInbound(
      first?.id ?? 0,
      first?.leaseId ?? "",
      "failed",
      "TRANSIENT",
      true,
      clock.now().toISOString(),
    );
    expect(
      store.leaseInbound("session", clock.now().toISOString(), 60),
    ).toBeUndefined();
    store.close();

    clock.advance(1_001);
    store = createStore(databasePath, { clock, retryBaseMs: 1_000 });
    const retried = store.leaseInbound(
      "session",
      clock.now().toISOString(),
      60,
    );
    expect(retried?.message.messageId).toBe("first");
    store.completeInbound(
      retried?.id ?? 0,
      retried?.leaseId ?? "",
      "completed",
      undefined,
      false,
      clock.now().toISOString(),
    );
    expect(
      store.leaseInbound("session", clock.now().toISOString(), 60)?.message
        .messageId,
    ).toBe("second");
    store.close();
  });

  it("blocks later work while an earlier durable reservation is recoverable", () => {
    const clock = new MutableClock();
    const store = createStore(undefined, {
      clock,
      reservationLeaseMs: 1_000,
      rateLimit: 10,
    });
    configure(store);
    const firstEnvelope = deferInboundMessage(message("first"));
    store.reserveInbound(firstEnvelope, clock.now().toISOString());
    clock.advance(1_001);
    const secondMessage = message("second");
    const second = store.reserveInbound(
      deferInboundMessage(secondMessage),
      clock.now().toISOString(),
    );
    store.finalizeInbound(second, secondMessage, clock.now().toISOString());
    expect(
      store.leaseInbound("session", clock.now().toISOString(), 60),
    ).toBeUndefined();
    const recovered = store.reserveInbound(
      firstEnvelope,
      clock.now().toISOString(),
    );
    store.finalizeInbound(
      recovered,
      message("first"),
      clock.now().toISOString(),
    );
    expect(
      store.leaseInbound("session", clock.now().toISOString(), 60)?.message
        .messageId,
    ).toBe("first");
    store.close();
  });

  it("recovers expired leases without overtaking and caps retries", () => {
    const clock = new MutableClock();
    const store = createStore(undefined, {
      clock,
      retryBaseMs: 10,
      maxAttempts: 2,
      ownershipLeaseMs: 60_000,
    });
    configure(store);
    admit(store, message("first"));
    admit(store, message("second"));
    expect(
      store.leaseInbound("session", clock.now().toISOString(), 10)?.message
        .messageId,
    ).toBe("first");
    clock.advance(10_001);
    expect(
      store.leaseInbound("session", clock.now().toISOString(), 10),
    ).toBeUndefined();
    clock.advance(11);
    const retry = store.leaseInbound(
      "session",
      clock.now().toISOString(),
      10,
    );
    expect(retry?.message.messageId).toBe("first");
    clock.advance(10_001);
    expect(
      store.leaseInbound("session", clock.now().toISOString(), 10)?.message
        .messageId,
    ).toBe("second");
    store.close();
  });

  it("binds approvals to full identity and operation scope", () => {
    const databasePath = createDatabasePath();
    const store = createStore(databasePath);
    const now = new Date(start).toISOString();
    const remoteIdentity = {
      ...identity(),
      sessionId: "session",
    };
    const scope: PermissionScope = {
      kind: "write",
      summary: "Write personal/src/index.ts",
      paths: ["personal/src/index.ts"],
      hosts: [],
      commands: [],
    };
    const created = store.createApproval({
      requestId: "request",
      nonce: "secure-nonce-value-12345",
      identity: remoteIdentity,
      scope,
      expiresAt: new Date(start + 300_000).toISOString(),
      now,
    });
    for (const mismatched of [
      { ...remoteIdentity, accountId: "bot-b" },
      { ...remoteIdentity, conversationId: "other-route" },
      { ...remoteIdentity, senderId: "other-sender" },
      { ...remoteIdentity, sessionId: "other-session" },
    ]) {
      expect(() =>
        store.decideApproval({
          nonce: "secure-nonce-value-12345",
          identity: mismatched,
          decision: "approved",
          now,
        }),
      ).toThrow("does not match");
    }
    store.decideApproval({
      nonce: "secure-nonce-value-12345",
      identity: remoteIdentity,
      decision: "approved",
      now,
    });
    expect(() =>
      store.decideApproval({
        nonce: "secure-nonce-value-12345",
        identity: remoteIdentity,
        decision: "approved",
        now,
      }),
    ).toThrow("already");
    expect(() =>
      store.consumeApproval({
        requestId: "request",
        identity: remoteIdentity,
        operationDigest: "0".repeat(64),
        now,
      }),
    ).toThrow("scope");
    expect(
      store.consumeApproval({
        requestId: "request",
        identity: remoteIdentity,
        operationDigest: created.operationDigest,
        now,
      })?.status,
    ).toBe("approved");
    store.close();

    const inspection = new DatabaseSync(databasePath);
    const nonce = inspection
      .prepare("SELECT nonce_hash FROM approvals WHERE request_id = 'request'")
      .get() as { nonce_hash: string };
    expect(nonce.nonce_hash).toHaveLength(64);
    expect(nonce.nonce_hash).not.toContain("secure-nonce");
    inspection.close();
  });

  it("fails closed for expired approval generations", () => {
    const store = createStore();
    const remoteIdentity = { ...identity(), sessionId: "session" };
    store.createApproval({
      requestId: "expired",
      nonce: "expired-nonce-value-12345",
      identity: remoteIdentity,
      scope: {
        kind: "network",
        summary: "Network example.test",
        paths: [],
        hosts: ["example.test"],
        commands: [],
      },
      expiresAt: new Date(start + 1_000).toISOString(),
      now: new Date(start).toISOString(),
    });

    expect(() =>
      store.decideApproval({
        nonce: "expired-nonce-value-12345",
        identity: remoteIdentity,
        decision: "approved",
        now: new Date(start + 1_001).toISOString(),
      }),
    ).toThrow("expired");
    store.close();
  });

  it("never consumes a decided approval after its expiry", () => {
    const store = createStore();
    const remoteIdentity = { ...identity(), sessionId: "session" };
    const scope: PermissionScope = {
      kind: "write",
      summary: "Write personal/file.txt",
      paths: ["personal/file.txt"],
      hosts: [],
      commands: [],
    };
    const created = store.createApproval({
      requestId: "decided-expiry",
      nonce: "decided-expiry-nonce-12345",
      identity: remoteIdentity,
      scope,
      expiresAt: new Date(start + 1_000).toISOString(),
      now: new Date(start).toISOString(),
    });
    store.decideApproval({
      nonce: "decided-expiry-nonce-12345",
      identity: remoteIdentity,
      decision: "approved",
      now: new Date(start + 500).toISOString(),
    });
    expect(
      store.consumeApproval({
        requestId: "decided-expiry",
        identity: remoteIdentity,
        operationDigest: created.operationDigest,
        now: new Date(start + 1_001).toISOString(),
      })?.status,
    ).toBe("denied");
    store.close();
  });

  it("removes terminal inbox and audit metadata after configured retention", () => {
    const store = createStore(undefined, {
      inboxRetentionDays: 1,
      auditRetentionDays: 1,
    });
    configure(store);
    admit(store, message("retained"));
    const leased = store.leaseInbound(
      "session",
      new Date(start).toISOString(),
      60,
    );
    store.completeInbound(
      leased?.id ?? 0,
      leased?.leaseId ?? "",
      "completed",
      undefined,
      false,
      new Date(start).toISOString(),
    );
    const later = new Date(start + 2 * 24 * 60 * 60 * 1_000).toISOString();
    expect(store.cleanup(later)).toMatchObject({
      inbox: 1,
    });
    expect(store.listAudit()).toEqual([]);
    expect(
      store.reserveInbound(deferInboundMessage(message("retained")), later)
        .disposition,
    ).toBe("reserved");
    store.close();
  });

  it("fails fast for a second owner and allows takeover after expiry", () => {
    const clock = new MutableClock();
    const databasePath = createDatabasePath();
    const first = createStore(databasePath, {
      clock,
      ownershipLeaseMs: 1_000,
      ownerId: "first",
    });
    expect(() =>
      createStore(databasePath, {
        clock,
        ownershipLeaseMs: 1_000,
        ownerId: "second",
      }),
    ).toThrow("owns this SQLite");
    clock.advance(1_001);
    const second = createStore(databasePath, {
      clock,
      ownershipLeaseMs: 1_000,
      ownerId: "second",
    });
    expect(() => first.renewOwnership()).toThrow("owns this SQLite");
    first.close();
    second.close();
  });

  it("migrates workspace data and quarantines ambiguous v1 identities", () => {
    const databasePath = createDatabasePath();
    const legacy = new DatabaseSync(databasePath);
    legacy.exec(`
      CREATE TABLE workspace_aliases (
        alias TEXT PRIMARY KEY, canonical_path TEXT NOT NULL,
        classification TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE allowed_senders (
        channel_id TEXT NOT NULL, sender_id TEXT NOT NULL, display_name TEXT,
        created_at TEXT NOT NULL, PRIMARY KEY (channel_id, sender_id)
      );
      CREATE TABLE session_bindings (
        route_key TEXT PRIMARY KEY, channel_id TEXT NOT NULL,
        conversation_id TEXT NOT NULL, session_id TEXT NOT NULL,
        workspace_alias TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE inbound_messages (
        id INTEGER PRIMARY KEY, channel_id TEXT NOT NULL, conversation_id TEXT NOT NULL,
        message_id TEXT NOT NULL, sender_id TEXT NOT NULL, received_at TEXT NOT NULL,
        text TEXT NOT NULL, attachments_json TEXT NOT NULL, status TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE approvals (
        request_id TEXT PRIMARY KEY, nonce_hash TEXT NOT NULL,
        identity_json TEXT NOT NULL, scope_json TEXT NOT NULL,
        status TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE audit_events (
        id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, event_type TEXT NOT NULL,
        actor TEXT NOT NULL, route_key TEXT, details_json TEXT NOT NULL
      );
      INSERT INTO workspace_aliases VALUES
        ('personal', 'C:\\repo', 'personal', '2026-08-24T00:00:00.000Z', '2026-08-24T00:00:00.000Z');
      INSERT INTO allowed_senders VALUES
        ('weixin-main', 'sender', NULL, '2026-08-24T00:00:00.000Z');
      INSERT INTO session_bindings VALUES
        ('weixin-main:conversation', 'weixin-main', 'conversation', 'session',
         'personal', '2026-08-24T00:00:00.000Z', '2026-08-24T00:00:00.000Z');
      INSERT INTO audit_events VALUES
        (1, '2026-08-24T00:00:00.000Z', 'legacy', 'sender', 'legacy:route', '{}');
    `);
    legacy.close();

    const store = createStore(databasePath);
    expect(store.getWorkspaceAlias("personal")?.classification).toBe("personal");
    expect(store.listAllowedSenders()).toEqual([]);
    expect(store.listBindings()).toEqual([]);
    expect(store.listAudit()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ eventType: "migration.v1.quarantined" }),
      ]),
    );
    configure(store, identity("bot-new"), "new-session");
    expect(store.getBinding(identity("bot-new"))?.sessionId).toBe("new-session");
    store.close();
  });
});
