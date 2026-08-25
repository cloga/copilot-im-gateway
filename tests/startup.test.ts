import { createServer, type Server } from "node:http";
import { DatabaseSync } from "node:sqlite";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type {
  ChannelHealth,
  ImChannelAdapter,
} from "../src/core/contracts.js";
import {
  reserveGatewayHttpServer,
} from "../src/daemon/http-server.js";
import { GatewayService } from "../src/daemon/gateway.js";
import {
  bootstrapGateway,
  parseGatewayPort,
} from "../src/daemon/startup.js";
import {
  GatewayStore,
  type GatewayStoreOptions,
} from "../src/daemon/store.js";

const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) {
    await cleanup();
  }
});

async function listen(server: Server, port = 0): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Test server did not expose a TCP address.");
  }
  return address.port;
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  });
}

async function availablePort(): Promise<number> {
  const probe = createServer();
  const port = await listen(probe);
  await closeServer(probe);
  return port;
}

function createLegacyV1Database(databasePath: string): void {
  const legacy = new DatabaseSync(databasePath);
  legacy.exec(`
    CREATE TABLE workspace_aliases (
      alias TEXT PRIMARY KEY, canonical_path TEXT NOT NULL,
      classification TEXT NOT NULL, created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE inbound_messages (
      id INTEGER PRIMARY KEY, channel_id TEXT NOT NULL,
      conversation_id TEXT NOT NULL, message_id TEXT NOT NULL,
      sender_id TEXT NOT NULL, received_at TEXT NOT NULL,
      text TEXT NOT NULL, attachments_json TEXT NOT NULL,
      status TEXT NOT NULL, created_at TEXT NOT NULL
    );
    INSERT INTO workspace_aliases VALUES
      ('personal', 'C:\\repo', 'personal',
       '2026-08-24T00:00:00.000Z', '2026-08-24T00:00:00.000Z');
    PRAGMA user_version = 1;
  `);
  legacy.close();
}

function pathsFor(directory: string): {
  dataDirectory: string;
  databasePath: string;
  tokenPath: string;
} {
  return {
    dataDirectory: directory,
    databasePath: path.join(directory, "gateway.sqlite"),
    tokenPath: path.join(directory, "auth-token"),
  };
}

interface Deferred {
  promise: Promise<void>;
  resolve(): void;
}

function createDeferred(): Deferred {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

class TrackingStore extends GatewayStore {
  closeCalls = 0;

  constructor(databasePath: string, options: GatewayStoreOptions) {
    super(databasePath, options);
  }

  override close(): void {
    this.closeCalls += 1;
    super.close();
  }
}

class ControlledLifecycleChannel implements ImChannelAdapter {
  readonly kind = "test";
  startCalls = 0;
  stopCalls = 0;
  healthReads = 0;
  #health: ChannelHealth = { state: "stopped" };

  constructor(
    readonly id: string,
    private readonly options: {
      startGate?: Promise<void>;
      stopGate?: Promise<void>;
      startError?: Error;
      stopError?: Error;
      onStart?: () => void;
      onStop?: () => void;
    } = {},
  ) {}

  async start(): Promise<void> {
    this.startCalls += 1;
    this.#health = {
      state: "starting",
      since: "2026-08-25T00:00:00.000Z",
    };
    this.options.onStart?.();
    await this.options.startGate;
    if (this.options.startError !== undefined) {
      this.#health = {
        state: "failed",
        since: "2026-08-25T00:00:00.000Z",
        errorCode: "START_FAILED",
      };
      throw this.options.startError;
    }
    this.#health = {
      state: "ready",
      since: "2026-08-25T00:00:00.000Z",
    };
  }

  async stop(): Promise<void> {
    this.stopCalls += 1;
    this.options.onStop?.();
    await this.options.stopGate;
    if (this.options.stopError !== undefined) {
      this.#health = {
        state: "failed",
        since: "2026-08-25T00:00:00.000Z",
        errorCode: "STOP_FAILED",
      };
      throw this.options.stopError;
    }
    this.#health = { state: "stopped" };
  }

  getHealth(): ChannelHealth {
    this.healthReads += 1;
    return this.#health;
  }

  async send(): Promise<void> {
    throw new Error("not available");
  }
}

class FailingChannel implements ImChannelAdapter {
  readonly id = "failing";
  readonly kind = "test";
  stopped = false;

  async start(): Promise<void> {
    throw new Error("channel start failed");
  }

  async stop(): Promise<void> {
    this.stopped = true;
  }

  getHealth(): ChannelHealth {
    return { state: "stopped" };
  }

  async send(): Promise<void> {
    throw new Error("not available");
  }
}

class SynchronouslyFailingLifecycleChannel implements ImChannelAdapter {
  readonly kind = "test";
  startCalls = 0;
  stopCalls = 0;
  healthReads = 0;

  constructor(readonly id: string) {}

  start(): Promise<void> {
    this.startCalls += 1;
    throw new Error("synchronous start failure");
  }

  stop(): Promise<void> {
    this.stopCalls += 1;
    throw new Error("synchronous stop failure");
  }

  getHealth(): ChannelHealth {
    this.healthReads += 1;
    return { state: "failed", errorCode: "SYNC_FAILURE", since: "2026-08-25T00:00:00.000Z" };
  }

  async send(): Promise<void> {
    throw new Error("not available");
  }
}

describe("gateway startup", () => {
  it("parses only valid configured loopback ports", () => {
    expect(parseGatewayPort(undefined)).toBe(32147);
    expect(parseGatewayPort("0")).toBe(0);
    expect(parseGatewayPort("65535")).toBe(65535);
    for (const invalid of ["-1", "1.5", "65536", "not-a-port"]) {
      expect(() => parseGatewayPort(invalid)).toThrow(
        "COPILOT_IM_GATEWAY_PORT",
      );
    }
  });

  it("serves not-ready until the reserved listener is activated", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "gateway-reserve-"));
    cleanups.push(() => rmSync(directory, { force: true, recursive: true }));
    const reservation = await reserveGatewayHttpServer(0);

    const starting = await fetch(`${reservation.url}/healthz`);
    expect(starting.status).toBe(503);
    expect(await starting.json()).toEqual({
      error: {
        code: "INTERNAL_ERROR",
        message: "The gateway is still starting.",
        retryable: true,
      },
      requestId: expect.any(String),
    });

    const store = new GatewayStore(path.join(directory, "gateway.sqlite"));
    const service = new GatewayService(store);
    const running = reservation.activate({
      service,
      bearerToken: "t".repeat(32),
    });
    cleanups.push(async () => {
      await running.close();
      store.close();
    });
    expect((await fetch(`${running.url}/healthz`)).status).toBe(200);
  });

  it("does not open or migrate a legacy database until the port is reserved", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "gateway-legacy-"));
    cleanups.push(() => rmSync(directory, { force: true, recursive: true }));
    const paths = pathsFor(directory);
    createLegacyV1Database(paths.databasePath);
    const before = readFileSync(paths.databasePath);
    const oldDaemon = createServer();
    const port = await listen(oldDaemon);
    cleanups.push(() => closeServer(oldDaemon));
    let tokenLoads = 0;

    await expect(
      bootstrapGateway({
        port,
        paths,
        loadBearerToken: () => {
          tokenLoads += 1;
          return "t".repeat(32);
        },
        createChannels: () => [],
      }),
    ).rejects.toMatchObject({ code: "EADDRINUSE" });

    expect(tokenLoads).toBe(0);
    expect(readFileSync(paths.databasePath)).toEqual(before);
    const unchanged = new DatabaseSync(paths.databasePath);
    expect(
      (
        unchanged.prepare("PRAGMA user_version").get() as {
          user_version: number;
        }
      ).user_version,
    ).toBe(1);
    expect(
      unchanged
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'gateway_ownership'",
        )
        .get(),
    ).toBeUndefined();
    unchanged.close();

    await closeServer(oldDaemon);
    const runtime = await bootstrapGateway({
      port,
      paths,
      loadBearerToken: () => "t".repeat(32),
      createChannels: () => [],
    });
    expect((await fetch(`${runtime.running.url}/healthz`)).status).toBe(200);
    await runtime.close();

    const migrated = new DatabaseSync(paths.databasePath);
    expect(
      (
        migrated.prepare("PRAGMA user_version").get() as {
          user_version: number;
        }
      ).user_version,
    ).toBe(3);
    expect(
      migrated
        .prepare(
          "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'gateway_ownership'",
        )
        .get(),
    ).toEqual({ present: 1 });
    migrated.close();
  });

  it("releases the reservation when store construction fails", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "gateway-store-fail-"));
    cleanups.push(() => rmSync(directory, { force: true, recursive: true }));
    const port = await availablePort();

    await expect(
      bootstrapGateway({
        port,
        paths: pathsFor(directory),
        loadBearerToken: () => "t".repeat(32),
        createStore: () => {
          throw new Error("store construction failed");
        },
        createChannels: () => [],
      }),
    ).rejects.toThrow("store construction failed");
    expect(existsSync(path.join(directory, "gateway.sqlite"))).toBe(false);

    const reservation = await reserveGatewayHttpServer(port);
    await reservation.close();
  });

  it("stops channels, closes the store, and releases the port after start fails", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "gateway-channel-fail-"));
    cleanups.push(() => rmSync(directory, { force: true, recursive: true }));
    const paths = pathsFor(directory);
    const port = await availablePort();
    const channel = new FailingChannel();

    await expect(
      bootstrapGateway({
        port,
        paths,
        loadBearerToken: () => "t".repeat(32),
        createChannels: () => [channel],
      }),
    ).rejects.toThrow("channel start failed");
    expect(channel.stopped).toBe(true);

    const reservation = await reserveGatewayHttpServer(port);
    await reservation.close();
    const reopened = new GatewayStore(paths.databasePath);
    reopened.close();
  });

  it("releases the listener and ownership for immediate restart after administrative shutdown", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "gateway-shutdown-"));
    cleanups.push(() => rmSync(directory, { force: true, recursive: true }));
    const paths = pathsFor(directory);
    const token = "t".repeat(32);
    const port = await availablePort();
    let shutdownComplete: () => void = () => undefined;
    const shutdownCompleted = new Promise<void>((resolve) => {
      shutdownComplete = resolve;
    });
    const runtime = await bootstrapGateway({
      port,
      paths,
      loadBearerToken: () => token,
      createChannels: () => [],
      onShutdown: async () => {
        await runtime.close();
        shutdownComplete();
      },
    });

    const response = await fetch(`${runtime.running.url}/v2/admin/shutdown`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status).toBe(202);
    await shutdownCompleted;

    const restarted = await bootstrapGateway({
      port,
      paths,
      loadBearerToken: () => token,
      createChannels: () => [],
    });
    expect((await fetch(`${restarted.running.url}/healthz`)).status).toBe(200);
    await restarted.close();
  });

  it("settles later adapters after synchronous start and stop failures before closing the store", async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "gateway-settled-"));
    cleanups.push(() => rmSync(directory, { force: true, recursive: true }));
    const paths = pathsFor(directory);
    const startGate = createDeferred();
    const stopGate = createDeferred();
    const delayedStartEntered = createDeferred();
    const delayedStopEntered = createDeferred();
    const failing = new SynchronouslyFailingLifecycleChannel("failing-lifecycle");
    const delayed = new ControlledLifecycleChannel("delayed-lifecycle", {
      startGate: startGate.promise,
      stopGate: stopGate.promise,
      onStart: delayedStartEntered.resolve,
      onStop: delayedStopEntered.resolve,
    });
    let store: TrackingStore | undefined;

    const starting = bootstrapGateway({
      port: 0,
      paths,
      loadBearerToken: () => "t".repeat(32),
      createStore: (databasePath, options) => {
        store = new TrackingStore(databasePath, options);
        return store;
      },
      createChannels: () => [failing, delayed],
    });
    let settled = false;
    void starting.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );

    await delayedStartEntered.promise;
    expect(failing.startCalls).toBe(1);
    expect(delayed.startCalls).toBe(1);
    expect(settled).toBe(false);
    expect(store?.closeCalls).toBe(0);

    startGate.resolve();
    await delayedStopEntered.promise;
    expect(failing.stopCalls).toBe(1);
    expect(delayed.stopCalls).toBe(1);
    expect(settled).toBe(false);
    expect(store?.closeCalls).toBe(0);

    stopGate.resolve();
    await expect(starting).rejects.toBeInstanceOf(AggregateError);
    expect(store?.closeCalls).toBe(1);
    expect(failing.healthReads).toBe(3);
    expect(delayed.healthReads).toBe(3);
  });
});
