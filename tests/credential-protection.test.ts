import { randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  AesGcmSecretCipher,
  SecretStateDecryptionError,
  type SecretCipher,
  type SecretStateIdentity,
} from "../src/core/secret-state.js";
import {
  FileMasterKeyStorage,
  keyId,
  loadOrCreateMasterKey,
  parseRotationJournal,
  recoverInterruptedRotation,
  resolveMasterKeyPaths,
  writeRotationJournal,
  type MasterKeyStorage,
  type RotationDurability,
  type RotationJournal,
} from "../src/daemon/master-key.js";
import { rotateCredentialMasterKey } from "../src/daemon/maintenance.js";
import { GatewayStore } from "../src/daemon/store.js";

const directories: string[] = [];
const identity = {
  tenantId: "local" as const,
  channelId: "weixin-main",
  accountId: "bot-a",
};

function temporaryDirectory(): string {
  const directory = mkdtempSync(path.join(os.tmpdir(), "gateway-secrets-"));
  directories.push(directory);
  return directory;
}

function createVersionThreeDatabase(databasePath: string): void {
  const database = new DatabaseSync(databasePath);
  database.exec(`
    CREATE TABLE channel_state (
      tenant_id TEXT NOT NULL,
      channel_id TEXT NOT NULL,
      account_id TEXT NOT NULL,
      state_key TEXT NOT NULL,
      value_json TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (tenant_id, channel_id, account_id, state_key)
    );
    CREATE TABLE active_channel_accounts (
      tenant_id TEXT NOT NULL,
      channel_id TEXT NOT NULL,
      account_id TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (tenant_id, channel_id)
    );
    INSERT INTO active_channel_accounts VALUES
      ('local', 'weixin-main', 'bot-a', '2026-08-25T00:00:00.000Z');
    INSERT INTO channel_state VALUES
      ('local', 'weixin-main', 'bot-a', 'credentials',
       '{"botToken":"fixture-secret-token","botId":"bot-a","baseUrl":"https://example.test","userId":"user-a"}',
       '2026-08-25T00:00:00.000Z'),
      ('local', 'weixin-main', 'bot-a', 'context:sender-a',
       '"fixture-context-token"', '2026-08-25T00:00:00.000Z');
    PRAGMA user_version = 3;
  `);
  database.close();
}

class FailingCipher implements SecretCipher {
  readonly keyId: string;
  #encryptions = 0;

  constructor(
    private readonly delegate: SecretCipher,
    private readonly failAt: number,
  ) {
    this.keyId = delegate.keyId;
  }

  encrypt(identityValue: SecretStateIdentity, value: unknown): string {
    this.#encryptions += 1;
    if (this.#encryptions === this.failAt) {
      throw new Error("injected encryption failure");
    }
    return this.delegate.encrypt(identityValue, value);
  }

  decrypt(identityValue: SecretStateIdentity, envelope: string): unknown {
    return this.delegate.decrypt(identityValue, envelope);
  }

  destroy(): void {
    this.delegate.destroy();
  }
}

class MemoryKeyStorage implements MasterKeyStorage {
  created = 0;
  value: Buffer | undefined;

  read(): Buffer | undefined {
    return this.value === undefined ? undefined : Buffer.from(this.value);
  }

  create(_keyPath: string, key: Buffer): void {
    this.created += 1;
    this.value = Buffer.from(key);
  }
}

class TestRotationDurability implements RotationDurability {
  #operation = 0;

  constructor(private readonly failAfterOperation?: number) {}

  writeJournal(rotationPath: string, journal: RotationJournal): void {
    writeRotationJournal(rotationPath, journal);
    this.#completeOperation();
  }

  rename(sourcePath: string, destinationPath: string): void {
    renameSync(sourcePath, destinationPath);
    this.#completeOperation();
  }

  remove(filePath: string): void {
    rmSync(filePath);
    this.#completeOperation();
  }

  #completeOperation(): void {
    this.#operation += 1;
    if (this.#operation === this.failAfterOperation) {
      throw new Error("injected directory sync failure");
    }
  }
}

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("credential state protection", () => {
  it("authenticates ciphertext, associated data, and key identity", () => {
    const first = new AesGcmSecretCipher(Buffer.alloc(32, 1), {
      randomBytes: () => Buffer.alloc(12, 2),
    });
    const second = new AesGcmSecretCipher(Buffer.alloc(32, 3));
    const record = { ...identity, stateKey: "credentials" };
    const envelope = first.encrypt(record, {
      botToken: "fixture-secret-token",
    });

    expect(envelope).not.toContain("fixture-secret-token");
    expect(first.decrypt(record, envelope)).toEqual({
      botToken: "fixture-secret-token",
    });
    expect(() =>
      first.decrypt({ ...record, accountId: "bot-b" }, envelope),
    ).toThrow(SecretStateDecryptionError);
    expect(() => second.decrypt(record, envelope)).toThrow(
      SecretStateDecryptionError,
    );

    const parsed = JSON.parse(envelope) as { ciphertext: string };
    parsed.ciphertext = `${parsed.ciphertext.slice(0, -1)}A`;
    expect(() => first.decrypt(record, JSON.stringify(parsed))).toThrow(
      SecretStateDecryptionError,
    );
    first.destroy();
    second.destroy();
  });

  it("migrates plaintext channel state transactionally and idempotently", () => {
    const directory = temporaryDirectory();
    const databasePath = path.join(directory, "gateway.sqlite");
    const key = Buffer.alloc(32, 4);
    createVersionThreeDatabase(databasePath);

    let store = new GatewayStore(databasePath, { secretKey: key });
    expect(
      store.getActiveChannelAccount<{
        botToken: string;
        userId: string;
      }>("local", "weixin-main"),
    ).toMatchObject({
      credentials: {
        botToken: "fixture-secret-token",
        userId: "user-a",
      },
    });
    expect(store.listActiveChannelAccounts()[0]?.userId).toBe("user-a");
    store.close();

    const bytes = readFileSync(databasePath);
    expect(bytes.includes(Buffer.from("fixture-secret-token"))).toBe(false);
    expect(bytes.includes(Buffer.from("fixture-context-token"))).toBe(false);
    const inspection = new DatabaseSync(databasePath);
    const row = inspection
      .prepare(
        `SELECT value_json, secret_version FROM channel_state
         WHERE state_key = 'credentials'`,
      )
      .get() as { value_json: string; secret_version: number };
    expect(row.secret_version).toBe(1);
    expect(JSON.parse(row.value_json)).toMatchObject({
      v: 1,
      alg: "A256GCM",
    });
    inspection.close();

    store = new GatewayStore(databasePath, { secretKey: key });
    expect(
      store.getChannelState(identity, "context:sender-a"),
    ).toBe("fixture-context-token");
    store.close();
  });

  it("fails startup when a reader prevents complete migration checkpointing and retries", () => {
    const directory = temporaryDirectory();
    const databasePath = path.join(directory, "gateway.sqlite");
    const key = Buffer.alloc(32, 15);
    createVersionThreeDatabase(databasePath);
    const setup = new DatabaseSync(databasePath);
    setup.exec("PRAGMA journal_mode = WAL");
    setup.close();
    const reader = new DatabaseSync(databasePath, { readOnly: true });
    reader.exec("BEGIN");
    expect(
      reader
        .prepare("SELECT value_json FROM channel_state WHERE state_key = ?")
        .get("credentials"),
    ).toBeDefined();

    try {
      expect(() => new GatewayStore(databasePath, { secretKey: key })).toThrow(
        "checkpoint could not complete",
      );
      expect(readFileSync(`${databasePath}-wal`).byteLength).toBeGreaterThan(0);
    } finally {
      reader.exec("ROLLBACK");
      reader.close();
    }

    const recovered = new GatewayStore(databasePath, { secretKey: key });
    expect(
      recovered.getChannelState<{ botToken: string }>(identity, "credentials")
        ?.botToken,
    ).toBe("fixture-secret-token");
    recovered.close();
    expect(
      !existsSync(`${databasePath}-wal`) ||
        readFileSync(`${databasePath}-wal`).byteLength === 0,
    ).toBe(true);
  });

  it("rolls back a failed migration and retries with the durable key", () => {
    const directory = temporaryDirectory();
    const databasePath = path.join(directory, "gateway.sqlite");
    createVersionThreeDatabase(databasePath);
    const key = Buffer.alloc(32, 5);
    const failing = new FailingCipher(new AesGcmSecretCipher(key), 2);

    expect(
      () => new GatewayStore(databasePath, { secretCipher: failing }),
    ).toThrow("injected encryption failure");
    const inspection = new DatabaseSync(databasePath);
    expect(
      (
        inspection.prepare("PRAGMA user_version").get() as {
          user_version: number;
        }
      ).user_version,
    ).toBe(3);
    expect(
      (
        inspection
          .prepare(
            `SELECT value_json FROM channel_state
             WHERE state_key = 'credentials'`,
          )
          .get() as { value_json: string }
      ).value_json,
    ).toContain("fixture-secret-token");
    inspection.close();

    const recovered = new GatewayStore(databasePath, { secretKey: key });
    expect(
      recovered.getChannelState(identity, "context:sender-a"),
    ).toBe("fixture-context-token");
    recovered.close();
  });

  it("fails closed for missing, wrong, tampered, or relocated state", () => {
    const directory = temporaryDirectory();
    const databasePath = path.join(directory, "gateway.sqlite");
    const key = Buffer.alloc(32, 6);
    const store = new GatewayStore(databasePath, { secretKey: key });
    store.setChannelState(
      identity,
      "credentials",
      { botToken: "fixture-secret-token" },
      "2026-08-25T00:00:00.000Z",
    );
    store.close();

    expect(
      () => new GatewayStore(databasePath, { secretKey: Buffer.alloc(32, 7) }),
    ).toThrow("does not match");

    const database = new DatabaseSync(databasePath);
    database
      .prepare(
        `UPDATE channel_state SET account_id = 'bot-b'
         WHERE state_key = 'credentials'`,
      )
      .run();
    database.close();
    expect(
      () => new GatewayStore(databasePath, { secretKey: key }),
    ).toThrow(SecretStateDecryptionError);

    const storage = new MemoryKeyStorage();
    expect(() =>
      loadOrCreateMasterKey({
        keyPath: path.join(directory, "missing-key"),
        databasePath,
        storage,
      }),
    ).toThrow("missing");
    expect(storage.created).toBe(0);
  });

  it("rolls back failed rotation and commits every record under one new key", () => {
    const databasePath = path.join(temporaryDirectory(), "gateway.sqlite");
    const oldKey = Buffer.alloc(32, 8);
    const newKey = Buffer.alloc(32, 9);
    const store = new GatewayStore(databasePath, { secretKey: oldKey });
    store.setChannelState(
      identity,
      "credentials",
      { botToken: "fixture-secret-token" },
      "2026-08-25T00:00:00.000Z",
    );
    store.setChannelState(
      identity,
      "context:sender-a",
      "fixture-context-token",
      "2026-08-25T00:00:00.000Z",
    );

    const failing = new FailingCipher(new AesGcmSecretCipher(newKey), 2);
    expect(() => store.rotateSecrets(failing)).toThrow(
      "injected encryption failure",
    );
    failing.destroy();
    expect(store.getChannelState(identity, "context:sender-a")).toBe(
      "fixture-context-token",
    );

    expect(store.rotateSecrets(new AesGcmSecretCipher(newKey))).toBe(2);
    store.close();
    expect(
      () => new GatewayStore(databasePath, { secretKey: oldKey }),
    ).toThrow("does not match");
    const rotated = new GatewayStore(databasePath, { secretKey: newKey });
    expect(rotated.getChannelState(identity, "context:sender-a")).toBe(
      "fixture-context-token",
    );
    rotated.close();
  });

  it("recovers the committed side of an interrupted key-file swap", () => {
    const directory = temporaryDirectory();
    const databasePath = path.join(directory, "gateway.sqlite");
    const oldKey = Buffer.alloc(32, 10);
    const newKey = Buffer.alloc(32, 11);
    const paths = resolveMasterKeyPaths(directory);
    writeFileSync(paths.keyPath, oldKey);
    writeFileSync(paths.nextKeyPath, newKey);

    const store = new GatewayStore(databasePath, { secretKey: oldKey });
    store.setChannelState(
      identity,
      "credentials",
      { botToken: "fixture-secret-token" },
      "2026-08-25T00:00:00.000Z",
    );
    store.rotateSecrets(new AesGcmSecretCipher(newKey));
    store.close();
    writeRotationJournal(paths.rotationPath, {
      version: 1,
      currentKeyId: keyId(oldKey),
      nextKeyId: keyId(newKey),
    });

    recoverInterruptedRotation(
      paths,
      databasePath,
      new FileMasterKeyStorage("win32", { NODE_ENV: "test" }),
      new TestRotationDurability(),
    );
    expect(readFileSync(paths.keyPath)).toEqual(newKey);
    expect(existsSync(paths.nextKeyPath)).toBe(false);
    expect(existsSync(paths.previousKeyPath)).toBe(false);
    expect(existsSync(paths.rotationPath)).toBe(false);

    const recovered = new GatewayStore(databasePath, { secretKey: newKey });
    expect(
      recovered.getChannelState<{ botToken: string }>(
        identity,
        "credentials",
      )?.botToken,
    ).toBe("fixture-secret-token");
    recovered.close();
  });

  it("rejects malicious or incomplete rotation journals without changing keys", () => {
    const oldKey = Buffer.alloc(32, 20);
    for (const journal of [
      '{"version":1,"currentKeyId":"invalid"}\n',
      `${JSON.stringify({
        version: 1,
        currentKeyId: keyId(oldKey),
        nextKeyId: "a".repeat(64),
        keyPath: "C:\\attacker-controlled",
      })}\n`,
    ]) {
      expect(() => parseRotationJournal(journal)).toThrow(
        "rotation journal is invalid",
      );
    }
  });

  it("rotates the durable key through the offline maintenance operation", () => {
    const directory = temporaryDirectory();
    chmodSync(directory, 0o700);
    const databasePath = path.join(directory, "gateway.sqlite");
    const paths = resolveMasterKeyPaths(directory);
    const oldKey = Buffer.alloc(32, 13);
    const newKey = Buffer.alloc(32, 14);
    writeFileSync(paths.keyPath, oldKey, { mode: 0o600 });
    writeFileSync(paths.nextKeyPath, newKey, { mode: 0o600 });
    chmodSync(paths.keyPath, 0o600);
    chmodSync(paths.nextKeyPath, 0o600);
    const store = new GatewayStore(databasePath, { secretKey: oldKey });
    store.setChannelState(
      identity,
      "credentials",
      { botToken: "fixture-secret-token" },
      "2026-08-25T00:00:00.000Z",
    );
    store.close();

    expect(
      rotateCredentialMasterKey(
        directory,
        { NODE_ENV: "test" },
        {
          durability: new TestRotationDurability(),
          platform: "win32",
        },
      ),
    ).toBe(1);
    const walPath = `${databasePath}-wal`;
    expect(
      !existsSync(walPath) || readFileSync(walPath).byteLength === 0,
    ).toBe(true);
    expect(readFileSync(paths.keyPath)).toEqual(newKey);
    expect(existsSync(paths.nextKeyPath)).toBe(false);
    const rotated = new GatewayStore(databasePath, { secretKey: newKey });
    expect(
      rotated.getChannelState<{ botToken: string }>(
        identity,
        "credentials",
      )?.botToken,
    ).toBe("fixture-secret-token");
    rotated.close();
  });

  it("does not re-encrypt before the rotation journal directory barrier", () => {
    const directory = temporaryDirectory();
    const databasePath = path.join(directory, "gateway.sqlite");
    const paths = resolveMasterKeyPaths(directory);
    const oldKey = Buffer.alloc(32, 16);
    const newKey = Buffer.alloc(32, 17);
    writeFileSync(paths.keyPath, oldKey);
    writeFileSync(paths.nextKeyPath, newKey);
    const store = new GatewayStore(databasePath, { secretKey: oldKey });
    store.setChannelState(
      identity,
      "credentials",
      { botToken: "fixture-secret-token" },
      "2026-08-25T00:00:00.000Z",
    );
    store.close();

    expect(() =>
      rotateCredentialMasterKey(
        directory,
        { NODE_ENV: "test" },
        {
          durability: new TestRotationDurability(1),
          platform: "win32",
        },
      ),
    ).toThrow("directory sync failure");
    const unchanged = new GatewayStore(databasePath, { secretKey: oldKey });
    unchanged.close();

    recoverInterruptedRotation(
      paths,
      databasePath,
      new FileMasterKeyStorage("win32", { NODE_ENV: "test" }),
      new TestRotationDurability(),
    );
    expect(readFileSync(paths.keyPath)).toEqual(oldKey);
    expect(existsSync(paths.nextKeyPath)).toBe(false);
    expect(existsSync(paths.rotationPath)).toBe(false);
  });

  it("recovers an interrupted offline rotation before accepting another request", () => {
    const directory = temporaryDirectory();
    const databasePath = path.join(directory, "gateway.sqlite");
    const paths = resolveMasterKeyPaths(directory);
    const oldKey = Buffer.alloc(32, 21);
    const newKey = Buffer.alloc(32, 22);
    writeFileSync(paths.keyPath, oldKey);
    writeFileSync(paths.nextKeyPath, newKey);
    const store = new GatewayStore(databasePath, { secretKey: oldKey });
    store.setChannelState(
      identity,
      "credentials",
      { botToken: "fixture-secret-token" },
      "2026-08-25T00:00:00.000Z",
    );
    store.close();

    expect(() =>
      rotateCredentialMasterKey(
        directory,
        { NODE_ENV: "test" },
        {
          durability: new TestRotationDurability(2),
          platform: "win32",
        },
      ),
    ).toThrow("directory sync failure");
    expect(existsSync(paths.keyPath)).toBe(false);
    expect(
      rotateCredentialMasterKey(
        directory,
        { NODE_ENV: "test" },
        {
          durability: new TestRotationDurability(),
          platform: "win32",
        },
      ),
    ).toBe(0);
    expect(readFileSync(paths.keyPath)).toEqual(newKey);
    const recovered = new GatewayStore(databasePath, { secretKey: newKey });
    recovered.close();
  });

  it.each([1, 2, 3, 4])(
    "repeats committed rotation recovery after durability failure %s",
    (failureOperation) => {
      const directory = temporaryDirectory();
      const databasePath = path.join(directory, "gateway.sqlite");
      const paths = resolveMasterKeyPaths(directory);
      const oldKey = Buffer.alloc(32, 18);
      const newKey = Buffer.alloc(32, 19);
      writeFileSync(paths.keyPath, oldKey);
      writeFileSync(paths.nextKeyPath, newKey);
      const store = new GatewayStore(databasePath, { secretKey: oldKey });
      store.setChannelState(
        identity,
        "credentials",
        { botToken: "fixture-secret-token" },
        "2026-08-25T00:00:00.000Z",
      );
      store.rotateSecrets(new AesGcmSecretCipher(newKey));
      store.close();
      writeRotationJournal(paths.rotationPath, {
        version: 1,
        currentKeyId: keyId(oldKey),
        nextKeyId: keyId(newKey),
      });
      const storage = new FileMasterKeyStorage("win32", { NODE_ENV: "test" });

      expect(() =>
        recoverInterruptedRotation(
          paths,
          databasePath,
          storage,
          new TestRotationDurability(failureOperation),
        ),
      ).toThrow("directory sync failure");
      recoverInterruptedRotation(
        paths,
        databasePath,
        storage,
        new TestRotationDurability(),
      );
      expect(readFileSync(paths.keyPath)).toEqual(newKey);
      expect(existsSync(paths.nextKeyPath)).toBe(false);
      expect(existsSync(paths.previousKeyPath)).toBe(false);
      expect(existsSync(paths.rotationPath)).toBe(false);
      const recovered = new GatewayStore(databasePath, { secretKey: newKey });
      recovered.close();
    },
  );

  it("requires explicit verified Windows ACL attestation", () => {
    const directory = temporaryDirectory();
    const keyPath = path.join(directory, "credential-master-key");
    writeFileSync(keyPath, randomBytes(32));
    const storage = new FileMasterKeyStorage("win32", {
      NODE_ENV: "production",
    });
    expect(() => storage.read(keyPath)).toThrow("ACL");
    expect(() =>
      storage.create(path.join(directory, "new-key"), randomBytes(32)),
    ).toThrow("ACL helper");
  });

  it("creates and reuses one durable key through an injected key store", () => {
    const directory = temporaryDirectory();
    const storage = new MemoryKeyStorage();
    const expected = Buffer.alloc(32, 12);
    const first = loadOrCreateMasterKey({
      keyPath: path.join(directory, "credential-master-key"),
      databasePath: path.join(directory, "gateway.sqlite"),
      storage,
      createRandomKey: () => Buffer.from(expected),
    });
    const second = loadOrCreateMasterKey({
      keyPath: path.join(directory, "credential-master-key"),
      databasePath: path.join(directory, "gateway.sqlite"),
      storage,
      createRandomKey: () => {
        throw new Error("key source must not run on reinstall");
      },
    });
    expect(first).toEqual(expected);
    expect(second).toEqual(expected);
    expect(storage.created).toBe(1);
    first.fill(0);
    second.fill(0);
  });
});
