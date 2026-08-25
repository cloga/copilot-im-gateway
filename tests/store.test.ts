import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalizeIdentityComponents,
  deferInboundMessage,
  toRouteKey,
  type ImInboundMessage,
  type MinimalInboundEnvelope,
  type RouteIdentity,
} from "../src/core/contracts.js";
import {
  hashSecret,
  type Clock,
  type PermissionScope,
} from "../src/core/security.js";
import { GatewayService } from "../src/daemon/gateway.js";
import {
  GatewayStore,
  type AdmissionResult,
  type GatewayStoreOptions,
  type ReservedAdmissionResult,
} from "../src/daemon/store.js";

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

function requireReserved(
  admission: AdmissionResult,
): ReservedAdmissionResult {
  if (admission.disposition !== "reserved") {
    throw new Error(`Expected reserved admission, got ${admission.disposition}`);
  }
  return admission;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("GatewayStore durable runtime state", () => {
  it("uses collision-safe account-aware routes for binding and idempotency", () => {
    const store = createStore();
    try {
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
    } finally {
      store.close();
    }
  }, 20_000);

  it("persists accepted idempotency while re-evaluating bounded rejections", () => {
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
      disposition: "rate_limited",
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

  it("atomically reclaims a prior owner's live reservation after restart", () => {
    const clock = new MutableClock();
    const databasePath = createDatabasePath();
    let store = createStore(databasePath, {
      clock,
      rateLimit: 1,
      reservationLeaseMs: 60_000,
    });
    configure(store);
    const envelope = deferInboundMessage(message("restart"));
    const original = requireReserved(
      store.reserveInbound(envelope, clock.now().toISOString()),
    );
    const inspection = new DatabaseSync(databasePath);
    expect(
      (
        inspection
          .prepare(
            "SELECT reservation_owner_token AS token FROM inbound_admissions",
          )
          .get() as { token: string }
      ).token,
    ).not.toHaveLength(0);
    inspection.close();
    store.close();

    store = createStore(databasePath, {
      clock,
      rateLimit: 1,
      reservationLeaseMs: 60_000,
    });
    const recovered = requireReserved(
      store.reserveInbound(envelope, clock.now().toISOString()),
    );
    expect(recovered).toMatchObject({
      disposition: "reserved",
      recovered: true,
      routeSequence: original.routeSequence,
    });
    expect(recovered.reservationId).not.toBe(original.reservationId);
    store.finalizeInbound(
      recovered,
      message("restart"),
      clock.now().toISOString(),
    );
    expect(
      store.leaseInbound("session", clock.now().toISOString(), 60)?.message
        .messageId,
    ).toBe("restart");
    store.close();
  });

  it("signals a retry without materializing a live reservation duplicate", async () => {
    const clock = new MutableClock();
    const store = createStore(undefined, { clock });
    configure(store);
    const inbound = message("still-materializing");
    store.reserveInbound(
      deferInboundMessage(inbound),
      clock.now().toISOString(),
    );
    let materialized = false;
    const service = new GatewayService(store, clock);
    await expect(
      service.onInbound({
        identity: identity(),
        messageId: inbound.messageId,
        receivedAt: inbound.receivedAt,
        materialize: async () => {
          materialized = true;
          return inbound;
        },
      }),
    ).rejects.toMatchObject({
      code: "MESSAGE_ADMISSION_IN_PROGRESS",
      retryable: true,
    });
    expect(materialized).toBe(false);
    store.close();
  });

  it("rematerializes after finalization loses an expired reservation", async () => {
    const clock = new MutableClock();
    const store = createStore(undefined, {
      clock,
      ownershipLeaseMs: 60_000,
      reservationLeaseMs: 1_000,
    });
    configure(store);
    const inbound = message("expired-during-materialization");
    let materializations = 0;
    const envelope: MinimalInboundEnvelope = {
      identity: identity(),
      messageId: inbound.messageId,
      receivedAt: inbound.receivedAt,
      materialize: async () => {
        materializations += 1;
        if (materializations === 1) {
          clock.advance(1_001);
        }
        return inbound;
      },
    };
    const service = new GatewayService(store, clock);

    await expect(service.onInbound(envelope)).rejects.toMatchObject({
      code: "STATE_CONFLICT",
      retryable: true,
    });
    await expect(service.onInbound(envelope)).resolves.toBeUndefined();
    expect(materializations).toBe(2);
    expect(
      store.leaseInbound("session", clock.now().toISOString(), 60)?.message
        .messageId,
    ).toBe(inbound.messageId);
    store.close();
  });

  it("does not fail materialization after its reservation expires", () => {
    const clock = new MutableClock();
    const store = createStore(undefined, {
      clock,
      ownershipLeaseMs: 60_000,
      reservationLeaseMs: 1_000,
    });
    configure(store);
    const inbound = message("expired-failure");
    const envelope = deferInboundMessage(inbound);
    const reservation = requireReserved(
      store.reserveInbound(envelope, clock.now().toISOString()),
    );
    clock.advance(1_001);

    let failure: unknown;
    try {
      store.failMaterialization(
        reservation,
        inbound.messageId,
        clock.now().toISOString(),
      );
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({
      code: "STATE_CONFLICT",
      retryable: true,
    });
    const recovered = requireReserved(
      store.reserveInbound(envelope, clock.now().toISOString()),
    );
    store.finalizeInbound(recovered, inbound, clock.now().toISOString());
    expect(
      store.leaseInbound("session", clock.now().toISOString(), 60)?.message
        .messageId,
    ).toBe(inbound.messageId);
    store.close();
  });

  it("rechecks sender authorization before route policy on owner recovery", () => {
    const clock = new MutableClock();
    const databasePath = createDatabasePath();
    let store = createStore(databasePath, { clock });
    configure(store);
    const envelope = deferInboundMessage(message("policy-sender"));
    store.reserveInbound(envelope, clock.now().toISOString());
    store.upsertWorkspaceAlias(
      "personal",
      "C:\\repo",
      "work",
      clock.now().toISOString(),
    );
    store.close();
    const database = new DatabaseSync(databasePath);
    database.prepare("DELETE FROM allowed_senders").run();
    database.close();

    store = createStore(databasePath, { clock });
    expect(
      store.reserveInbound(envelope, clock.now().toISOString()).disposition,
    ).toBe("denied");
    store.close();
  });

  it("rechecks personal binding, durable rate, and capacity on recovery", () => {
    const clock = new MutableClock();

    const routeDatabasePath = createDatabasePath();
    let routeStore = createStore(routeDatabasePath, { clock });
    configure(routeStore);
    const routeEnvelope = deferInboundMessage(message("policy-route"));
    routeStore.reserveInbound(routeEnvelope, clock.now().toISOString());
    routeStore.upsertWorkspaceAlias(
      "personal",
      "C:\\repo",
      "work",
      clock.now().toISOString(),
    );
    routeStore.close();
    routeStore = createStore(routeDatabasePath, { clock });
    expect(
      routeStore.reserveInbound(routeEnvelope, clock.now().toISOString())
        .disposition,
    ).toBe("route_denied");
    routeStore.close();

    const rateDatabasePath = createDatabasePath();
    let rateStore = createStore(rateDatabasePath, { clock, rateLimit: 10 });
    const firstRateRoute = identity("bot-rate", "first-rate");
    const secondRateRoute = identity("bot-rate", "second-rate");
    configure(rateStore, firstRateRoute, "session");
    configure(rateStore, secondRateRoute, "session");
    const firstRateEnvelope = deferInboundMessage(
      message("first-rate", firstRateRoute),
    );
    rateStore.reserveInbound(firstRateEnvelope, clock.now().toISOString());
    rateStore.reserveInbound(
      deferInboundMessage(message("second-rate", secondRateRoute)),
      clock.now().toISOString(),
    );
    rateStore.close();
    rateStore = createStore(rateDatabasePath, { clock, rateLimit: 1 });
    expect(
      rateStore.reserveInbound(firstRateEnvelope, clock.now().toISOString())
        .disposition,
    ).toBe("rate_limited");
    rateStore.close();

    const capacityDatabasePath = createDatabasePath();
    let capacityStore = createStore(capacityDatabasePath, {
      clock,
      rateLimit: 10,
      reservationLeaseMs: 1_000,
      maxPendingGlobal: 10,
    });
    const firstCapacityRoute = identity(
      "bot-capacity",
      "first-capacity",
      "first-sender",
    );
    const secondCapacityRoute = identity(
      "bot-capacity",
      "second-capacity",
      "second-sender",
    );
    configure(capacityStore, firstCapacityRoute, "session");
    configure(capacityStore, secondCapacityRoute, "session");
    const firstCapacityEnvelope = deferInboundMessage(
      message("first-capacity", firstCapacityRoute),
    );
    capacityStore.reserveInbound(
      firstCapacityEnvelope,
      clock.now().toISOString(),
    );
    clock.advance(1_001);
    capacityStore.reserveInbound(
      deferInboundMessage(message("second-capacity", secondCapacityRoute)),
      clock.now().toISOString(),
    );
    capacityStore.close();
    capacityStore = createStore(capacityDatabasePath, {
      clock,
      rateLimit: 10,
      reservationLeaseMs: 1_000,
      maxPendingGlobal: 1,
    });
    expect(
      capacityStore.reserveInbound(
        firstCapacityEnvelope,
        clock.now().toISOString(),
      ).disposition,
    ).toBe("capacity_rejected");
    capacityStore.close();
  });

  it("bounds unauthorized rejection persistence without materializing bodies", async () => {
    const clock = new MutableClock();
    const databasePath = createDatabasePath();
    const store = createStore(databasePath, {
      clock,
      maxRejectionBuckets: 8,
      rejectionRetentionDays: 1,
    });
    let materializations = 0;
    try {
      const service = new GatewayService(store, clock);
      for (let index = 0; index < 100; index += 1) {
        const route = identity(
          `bot-${index}`,
          `conversation-${index}`,
          `sender-${index}`,
        );
        await expect(
          service.onInbound({
            identity: route,
            messageId: `rejected-${index}`,
            receivedAt: clock.now().toISOString(),
            materialize: async () => {
              materializations += 1;
              return message(
                `rejected-${index}`,
                route,
                `rejected-secret-body-${index}`,
              );
            },
          }),
        ).rejects.toMatchObject({ code: "SENDER_NOT_ALLOWED" });
      }
      expect(materializations).toBe(0);
      const boundedInspection = new DatabaseSync(databasePath);
      try {
        expect(
          (
            boundedInspection
              .prepare("SELECT COUNT(*) AS count FROM admission_rejections")
              .get() as { count: number }
          ).count,
        ).toBe(8);
      } finally {
        boundedInspection.close();
      }

      clock.advance(24 * 60 * 60 * 1_000 + 1);
      store.renewOwnership();
      await expect(
        service.onInbound({
          identity: identity("new-bot", "new-conversation", "new-sender"),
          messageId: "after-retention",
          receivedAt: clock.now().toISOString(),
          materialize: async () => {
            materializations += 1;
            return message("after-retention");
          },
        }),
      ).rejects.toMatchObject({ code: "SENDER_NOT_ALLOWED" });
      expect(materializations).toBe(0);
    } finally {
      store.close();
    }

    const database = new DatabaseSync(databasePath);
    try {
      expect(
        (
          database
            .prepare("SELECT COUNT(*) AS count FROM inbound_admissions")
            .get() as { count: number }
        ).count,
      ).toBe(0);
      expect(
        (
          database
            .prepare("SELECT COUNT(*) AS count FROM admission_rejections")
            .get() as { count: number }
        ).count,
      ).toBe(1);
      expect(
        (
          database.prepare("SELECT COUNT(*) AS count FROM audit_events").get() as {
            count: number;
          }
        ).count,
      ).toBe(0);
      expect(
        JSON.stringify(
          database.prepare("SELECT * FROM admission_rejections").all(),
        ),
      ).not.toContain("rejected-secret-body");
    } finally {
      database.close();
    }
  }, 20_000);

  it("composes nested transactions with savepoint rollback semantics", () => {
    const store = createStore();
    const now = new Date(start).toISOString();
    store.transaction(() => {
      store.upsertWorkspaceAlias("personal", "C:\\repo", "personal", now);
      store.transaction(() => {
        store.allowSender(identity(), undefined, now);
      });
      store.upsertBinding(
        {
          ...identity(),
          sessionId: "session",
          workspaceAlias: "personal",
        },
        now,
      );
    });
    expect(store.listBindings()).toHaveLength(1);

    store.transaction(() => {
      try {
        store.transaction(() => {
          store.upsertBinding(
            {
              ...identity("bot-inner"),
              sessionId: "inner",
              workspaceAlias: "missing",
            },
            now,
          );
        });
      } catch {
        store.allowSender(identity("bot-caught"), undefined, now);
      }
    });
    expect(store.getBinding(identity("bot-inner"))).toBeUndefined();
    expect(
      store
        .listAllowedSenders()
        .some((sender) => sender.accountId === "bot-caught"),
    ).toBe(true);

    expect(() =>
      store.transaction(() => {
        store.upsertWorkspaceAlias("rolled-back", "C:\\rolled", "personal", now);
        store.transaction(() => {
          store.upsertBinding(
            {
              ...identity("bot-uncaught"),
              sessionId: "uncaught",
              workspaceAlias: "missing",
            },
            now,
          );
        });
      }),
    ).toThrow();
    expect(store.getWorkspaceAlias("rolled-back")).toBeUndefined();
    store.close();
  });

  it("does not mask an operation error when rollback itself cannot run", () => {
    const store = createStore();
    const original = new Error("original transaction failure");
    expect(() =>
      store.transaction(() => {
        store.close();
        throw original;
      }),
    ).toThrow(original);
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

  it("uses persisted reservation sequences when finalizing FIFO messages", () => {
    const store = createStore(undefined, { rateLimit: 10 });
    configure(store);
    const now = new Date(start).toISOString();
    const firstMessage = message("persisted-first");
    const secondMessage = message("persisted-second");
    const first = requireReserved(
      store.reserveInbound(deferInboundMessage(firstMessage), now),
    );
    const second = requireReserved(
      store.reserveInbound(deferInboundMessage(secondMessage), now),
    );
    first.routeSequence = 200;
    second.routeSequence = 100;

    store.finalizeInbound(first, firstMessage, now);
    store.finalizeInbound(second, secondMessage, now);
    const firstLease = store.leaseInbound("session", now, 60);
    expect(firstLease?.message.messageId).toBe(firstMessage.messageId);
    store.completeInbound(
      firstLease?.id ?? 0,
      firstLease?.leaseId ?? "",
      "completed",
      undefined,
      false,
      now,
    );
    expect(
      store.leaseInbound("session", now, 60)?.message.messageId,
    ).toBe(secondMessage.messageId);
    store.close();
  });

  it("recovers an expired reservation without changing its FIFO sequence", () => {
    const clock = new MutableClock();
    const store = createStore(undefined, {
      clock,
      reservationLeaseMs: 1_000,
      rateLimit: 10,
    });
    configure(store);
    const firstEnvelope = deferInboundMessage(message("first"));
    store.reserveInbound(firstEnvelope, clock.now().toISOString());
    const original = store.reserveInbound(firstEnvelope, clock.now().toISOString());
    if (original.disposition !== "in_progress") {
      throw new Error("Expected the live reservation to remain in progress.");
    }
    clock.advance(1_001);
    const recovered = requireReserved(
      store.reserveInbound(
        firstEnvelope,
        clock.now().toISOString(),
      ),
    );
    expect(recovered).toMatchObject({
      disposition: "reserved",
      recovered: true,
      routeSequence: original.routeSequence,
    });
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

  it("explicitly expires abandoned reservation barriers before leasing later work", () => {
    const clock = new MutableClock();
    const store = createStore(undefined, {
      clock,
      reservationLeaseMs: 1_000,
      rateLimit: 10,
    });
    configure(store);
    store.reserveInbound(
      deferInboundMessage(message("abandoned")),
      clock.now().toISOString(),
    );
    clock.advance(1_001);
    const laterMessage = message("later");
    const later = requireReserved(
      store.reserveInbound(
        deferInboundMessage(laterMessage),
        clock.now().toISOString(),
      ),
    );
    store.finalizeInbound(later, laterMessage, clock.now().toISOString());

    expect(
      store.leaseInbound("session", clock.now().toISOString(), 60)?.message
        .messageId,
    ).toBe("later");
    expect(store.listAudit()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          eventType: "inbound.reservation_expired",
        }),
      ]),
    );
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

  it("renews a matching owner after a clock stall and rejects it after takeover", () => {
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
    expect(() => first.renewOwnership()).not.toThrow();
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

  it("upgrades existing v2 admission ownership and rate-event columns", () => {
    const databasePath = createDatabasePath();
    const versionTwo = new DatabaseSync(databasePath);
    versionTwo.exec(`
      CREATE TABLE inbound_admissions (
        route_key TEXT NOT NULL,
        message_id_hash TEXT NOT NULL,
        disposition TEXT NOT NULL,
        reservation_id TEXT,
        reservation_expires_at TEXT,
        route_sequence INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (route_key, message_id_hash)
      );
      CREATE TABLE rate_events (
        sender_key TEXT NOT NULL,
        occurred_at TEXT NOT NULL
      );
      PRAGMA user_version = 2;
    `);
    versionTwo.close();

    const store = createStore(databasePath);
    store.close();
    const upgraded = new DatabaseSync(databasePath);
    expect(
      (
        upgraded.prepare("PRAGMA user_version").get() as {
          user_version: number;
        }
      ).user_version,
    ).toBe(3);
    expect(
      (
        upgraded.prepare("PRAGMA table_info(inbound_admissions)").all() as Array<{
          name: string;
        }>
      ).map((column) => column.name),
    ).toContain("reservation_owner_token");
    expect(
      (
        upgraded.prepare("PRAGMA table_info(rate_events)").all() as Array<{
          name: string;
        }>
      ).map((column) => column.name),
    ).toEqual(
      expect.arrayContaining(["route_key", "message_id_hash"]),
    );
    upgraded.close();
  });

  it("does not migrate state while a live prior-version owner holds the database", () => {
    const databasePath = createDatabasePath();
    const versionTwo = new DatabaseSync(databasePath);
    versionTwo.exec(`
      CREATE TABLE gateway_ownership (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        owner_token TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        renewed_at TEXT NOT NULL
      );
      CREATE TABLE rate_events (
        sender_key TEXT NOT NULL,
        occurred_at TEXT NOT NULL
      );
      INSERT INTO gateway_ownership VALUES
        (1, 'live-old-token', 'old-daemon', '2026-08-24T00:01:00.000Z',
         '2026-08-24T00:00:00.000Z');
      INSERT INTO rate_events VALUES
        ('sender', '2026-08-24T00:00:00.000Z');
      PRAGMA user_version = 2;
    `);
    versionTwo.close();

    expect(() =>
      createStore(databasePath, {
        clock: new MutableClock(),
        ownerId: "replacement",
      }),
    ).toThrow("owns this SQLite");

    const inspection = new DatabaseSync(databasePath);
    expect(
      (
        inspection.prepare("PRAGMA user_version").get() as {
          user_version: number;
        }
      ).user_version,
    ).toBe(2);
    expect(
      (
        inspection.prepare("SELECT COUNT(*) AS count FROM rate_events").get() as {
          count: number;
        }
      ).count,
    ).toBe(1);
    expect(
      (
        inspection.prepare("PRAGMA table_info(rate_events)").all() as Array<{
          name: string;
        }>
      ).map((column) => column.name),
    ).toEqual(["sender_key", "occurred_at"]);
    inspection.close();
  });

  it("discards uncorrelated v2 rate events before reclaiming once", () => {
    const databasePath = createDatabasePath();
    const route = identity();
    const routeKey = toRouteKey(route);
    const messageIdHash = hashSecret("legacy-reservation", "message-id");
    const senderKey = hashSecret(
      canonicalizeIdentityComponents([
        route.tenantId,
        route.channelId,
        route.accountId,
        route.senderId,
      ]),
      "rate-limit-sender",
    );
    const now = new Date(start).toISOString();
    const versionTwo = new DatabaseSync(databasePath);
    versionTwo.exec(`
      CREATE TABLE inbound_admissions (
        route_key TEXT NOT NULL,
        message_id_hash TEXT NOT NULL,
        disposition TEXT NOT NULL,
        reservation_id TEXT,
        reservation_expires_at TEXT,
        route_sequence INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (route_key, message_id_hash)
      );
      CREATE TABLE rate_events (
        sender_key TEXT NOT NULL,
        occurred_at TEXT NOT NULL
      );
      PRAGMA user_version = 2;
    `);
    versionTwo
      .prepare(
        `INSERT INTO inbound_admissions
           (route_key, message_id_hash, disposition, reservation_id,
            reservation_expires_at, route_sequence, created_at, updated_at)
         VALUES (?, ?, 'reserved', 'legacy-owner', ?, 1, ?, ?)`,
      )
      .run(
        routeKey,
        messageIdHash,
        new Date(start + 60_000).toISOString(),
        now,
        now,
      );
    versionTwo
      .prepare(
        "INSERT INTO rate_events (sender_key, occurred_at) VALUES (?, ?)",
      )
      .run(senderKey, now);
    versionTwo.close();

    const store = createStore(databasePath, { rateLimit: 1 });
    configure(store, route);
    const inbound = message("legacy-reservation", route);
    const envelope = deferInboundMessage(inbound);
    const recovered = requireReserved(store.reserveInbound(envelope, now));
    expect(recovered.recovered).toBe(true);
    expect(store.reserveInbound(envelope, now).disposition).toBe("in_progress");
    store.finalizeInbound(recovered, inbound, now);
    const inspection = new DatabaseSync(databasePath);
    expect(
      (
        inspection.prepare("SELECT COUNT(*) AS count FROM rate_events").get() as {
          count: number;
        }
      ).count,
    ).toBe(1);
    expect(
      inspection
        .prepare(
          `SELECT route_key, message_id_hash FROM rate_events
           WHERE route_key IS NOT NULL AND message_id_hash IS NOT NULL`,
        )
        .all(),
    ).toHaveLength(1);
    inspection.close();
    store.close();
  });

  it("repairs legacy audit index ownership on upgrade and current reopen", () => {
    const databasePath = createDatabasePath();
    const versionTwo = new DatabaseSync(databasePath);
    versionTwo.exec(`
      CREATE TABLE audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        event_type TEXT NOT NULL,
        actor TEXT NOT NULL,
        route_key TEXT,
        details_json TEXT NOT NULL
      );
      CREATE TABLE legacy_v1_audit_events (
        id INTEGER PRIMARY KEY,
        created_at TEXT NOT NULL,
        event_type TEXT NOT NULL,
        actor TEXT NOT NULL,
        route_key TEXT,
        details_json TEXT NOT NULL
      );
      CREATE INDEX idx_audit_created_at
        ON legacy_v1_audit_events(created_at DESC);
      PRAGMA user_version = 2;
    `);
    versionTwo.close();

    for (const reopenCurrent of [false, true]) {
      const store = createStore(databasePath);
      store.close();
      const inspection = new DatabaseSync(databasePath);
      expect(
        (
          inspection.prepare("PRAGMA index_list(audit_events)").all() as Array<{
            name: string;
          }>
        ).map((index) => index.name),
      ).toContain("idx_audit_created_at");
      expect(
        inspection.prepare("PRAGMA index_info(idx_audit_created_at)").all(),
      ).toEqual([expect.objectContaining({ name: "created_at" })]);
      expect(
        inspection
          .prepare(
            `SELECT tbl_name FROM sqlite_master
             WHERE type = 'index' AND name = 'idx_audit_created_at'`,
          )
          .get(),
      ).toEqual({ tbl_name: "audit_events" });
      if (!reopenCurrent) {
        inspection.exec(`
          DROP INDEX idx_audit_created_at;
          CREATE INDEX idx_audit_created_at
            ON legacy_v1_audit_events(created_at DESC);
        `);
      }
      inspection.close();
    }
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
      CREATE INDEX idx_inbound_status
        ON inbound_messages(status, created_at);
      CREATE INDEX idx_audit_created_at
        ON audit_events(created_at DESC);
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

    const migrated = new DatabaseSync(databasePath);
    const indexes = migrated
      .prepare("PRAGMA index_list(audit_events)")
      .all() as Array<{ name: string }>;
    expect(indexes.map((index) => index.name)).toContain(
      "idx_audit_created_at",
    );
    expect(
      migrated.prepare("PRAGMA index_info(idx_audit_created_at)").all(),
    ).toEqual([
      expect.objectContaining({ name: "created_at" }),
    ]);
    expect(
      migrated
        .prepare(
          "SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = 'idx_audit_created_at'",
        )
        .get(),
    ).toEqual({ tbl_name: "audit_events" });
    migrated.close();
  });
});
