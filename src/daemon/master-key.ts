import {
  chmodSync,
  closeSync,
  existsSync,
  fchmodSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const keyBytes = 32;
const encryptedSchemaVersion = 4;
const windowsAclAttestation = "operator-only-v1";

export interface MasterKeyPaths {
  keyPath: string;
  nextKeyPath: string;
  previousKeyPath: string;
  rotationPath: string;
}

export interface MasterKeyStorage {
  read(keyPath: string): Buffer | undefined;
  create(keyPath: string, key: Buffer): void;
}

export interface LoadMasterKeyOptions {
  keyPath: string;
  databasePath: string;
  platform?: NodeJS.Platform;
  environment?: NodeJS.ProcessEnv;
  storage?: MasterKeyStorage;
  createRandomKey?: () => Buffer;
}

export function resolveMasterKeyPaths(dataDirectory: string): MasterKeyPaths {
  const keyPath = path.join(dataDirectory, "credential-master-key");
  return {
    keyPath,
    nextKeyPath: `${keyPath}.next`,
    previousKeyPath: `${keyPath}.previous`,
    rotationPath: `${keyPath}.rotation`,
  };
}

export function loadOrCreateMasterKey(options: LoadMasterKeyOptions): Buffer {
  const platform = options.platform ?? process.platform;
  const storage =
    options.storage ??
    new FileMasterKeyStorage(
      platform,
      options.environment ?? process.env,
    );
  if (options.storage === undefined) {
    recoverInterruptedRotation(
      resolveMasterKeyPaths(path.dirname(options.keyPath)),
      options.databasePath,
      storage,
    );
  }
  const existing = storage.read(options.keyPath);
  if (existing !== undefined) {
    return validateKey(existing);
  }
  if (databaseRequiresMasterKey(options.databasePath)) {
    throw new Error(
      "Credential master key is missing for an encrypted gateway database.",
    );
  }
  const key = validateKey(
    (options.createRandomKey ?? (() => randomBytes(keyBytes)))(),
  );
  try {
    storage.create(options.keyPath, key);
    return key;
  } catch (error) {
    key.fill(0);
    throw error;
  }
}

interface RotationJournal {
    version: 1;
    currentKeyId: string;
    nextKeyId: string;
  }

export function recoverInterruptedRotation(
    paths: MasterKeyPaths,
    databasePath: string,
    storage: MasterKeyStorage,
  ): void {
    if (!existsSync(paths.rotationPath)) {
      return;
    }
    const journal = parseRotationJournal(
      readFileSync(paths.rotationPath, "utf8"),
    );
    const databaseKeyId = readDatabaseCredentialKeyId(databasePath);
    const current = storage.read(paths.keyPath);
    const next = storage.read(paths.nextKeyPath);
    const previous = storage.read(paths.previousKeyPath);
    try {
      if (databaseKeyId === journal.currentKeyId) {
        if (current === undefined || keyId(current) !== journal.currentKeyId) {
          throw new Error("Credential rotation recovery cannot find the current key.");
        }
        rmSync(paths.nextKeyPath, { force: true });
        rmSync(paths.previousKeyPath, { force: true });
        rmSync(paths.rotationPath);
        return;
      }
      if (databaseKeyId !== journal.nextKeyId) {
        throw new Error(
          "Credential rotation journal does not match the gateway database.",
        );
      }
      if (current !== undefined && keyId(current) === journal.nextKeyId) {
        rmSync(paths.nextKeyPath, { force: true });
      } else {
        if (next === undefined || keyId(next) !== journal.nextKeyId) {
          throw new Error("Credential rotation recovery cannot find the next key.");
        }
        if (current !== undefined) {
          if (keyId(current) !== journal.currentKeyId) {
            throw new Error(
              "Credential rotation recovery found an unexpected current key.",
            );
          }
          renameSync(paths.keyPath, paths.previousKeyPath);
        } else if (
          previous === undefined ||
          keyId(previous) !== journal.currentKeyId
        ) {
          throw new Error(
            "Credential rotation recovery cannot prove the prior key identity.",
          );
        }
        renameSync(paths.nextKeyPath, paths.keyPath);
      }
      rmSync(paths.previousKeyPath, { force: true });
      rmSync(paths.rotationPath);
    } finally {
      current?.fill(0);
      next?.fill(0);
      previous?.fill(0);
    }
  }

export function writeRotationJournal(
    rotationPath: string,
    journal: RotationJournal,
  ): void {
    const descriptor = openSync(rotationPath, "wx", 0o600);
    try {
      writeFileSync(descriptor, `${JSON.stringify(journal)}\n`, "utf8");
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
  }

export function readDatabaseCredentialKeyId(
    databasePath: string,
  ): string | undefined {
    if (!existsSync(databasePath)) {
      return undefined;
    }
    const database = new DatabaseSync(databasePath, { readOnly: true });
    try {
      if (
        database
          .prepare(
            `SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'gateway_metadata'`,
          )
          .get() === undefined
      ) {
        return undefined;
      }
      return (
        database
          .prepare(
            `SELECT metadata_value FROM gateway_metadata
             WHERE metadata_key = 'credential_key_id'`,
          )
          .get() as { metadata_value: string } | undefined
      )?.metadata_value;
    } finally {
      database.close();
    }
  }

export function keyId(key: Uint8Array): string {
    return createHash("sha256").update(key).digest("hex");
  }

function parseRotationJournal(value: string): RotationJournal {
    const parsed = JSON.parse(value) as Partial<RotationJournal>;
    if (
      parsed.version !== 1 ||
      typeof parsed.currentKeyId !== "string" ||
      !/^[a-f0-9]{64}$/u.test(parsed.currentKeyId) ||
      typeof parsed.nextKeyId !== "string" ||
      !/^[a-f0-9]{64}$/u.test(parsed.nextKeyId)
    ) {
      throw new Error("Credential rotation journal is invalid.");
    }
    return {
      version: 1,
      currentKeyId: parsed.currentKeyId,
      nextKeyId: parsed.nextKeyId,
    };
  }
export function databaseRequiresMasterKey(databasePath: string): boolean {
  if (!existsSync(databasePath)) {
    return false;
  }
  const database = new DatabaseSync(databasePath, { readOnly: true });
  try {
    const version = (
      database.prepare("PRAGMA user_version").get() as { user_version: number }
    ).user_version;
    return version >= encryptedSchemaVersion;
  } finally {
    database.close();
  }
}

export class FileMasterKeyStorage implements MasterKeyStorage {
  readonly #platform: NodeJS.Platform;
  readonly #environment: NodeJS.ProcessEnv;

  constructor(
    platform: NodeJS.Platform = process.platform,
    environment: NodeJS.ProcessEnv = process.env,
  ) {
    this.#platform = platform;
    this.#environment = environment;
  }

  read(keyPath: string): Buffer | undefined {
    try {
      this.#validateProtection(keyPath);
      return readFileSync(keyPath);
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        return undefined;
      }
      if (isSafeKeyError(error)) {
        throw error;
      }
      throw new Error("Credential master key could not be read securely.");
    }
  }

  create(keyPath: string, key: Buffer): void {
    if (this.#platform === "win32") {
      if (this.#environment.NODE_ENV === "test") {
        mkdirSync(path.dirname(keyPath), { recursive: true });
        const descriptor = openSync(keyPath, "wx");
        try {
          writeFileSync(descriptor, key);
          fsyncSync(descriptor);
        } finally {
          closeSync(descriptor);
        }
        return;
      }
      throw new Error(
        "Windows credential key provisioning requires the bundled operator ACL helper.",
      );
    }
    try {
      const directory = path.dirname(keyPath);
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const directoryStatus = lstatSync(directory);
      if (
        !directoryStatus.isDirectory() ||
        directoryStatus.isSymbolicLink() ||
        (typeof process.getuid === "function" &&
          directoryStatus.uid !== process.getuid())
      ) {
        throw new Error(
          "Credential key directory must be owned by the current user.",
        );
      }
      chmodSync(directory, 0o700);
      this.#validatePosixDirectory(directory);
      const temporaryPath = `${keyPath}.create-${process.pid}`;
      let descriptor: number | undefined;
      try {
        descriptor = openSync(temporaryPath, "wx", 0o600);
        fchmodSync(descriptor, 0o600);
        writeFileSync(descriptor, key);
        fsyncSync(descriptor);
        closeSync(descriptor);
        descriptor = undefined;
        linkSync(temporaryPath, keyPath);
        rmSync(temporaryPath);
        chmodSync(keyPath, 0o600);
        const directoryDescriptor = openSync(directory, "r");
        try {
          fsyncSync(directoryDescriptor);
        } finally {
          closeSync(directoryDescriptor);
        }
        this.#validateProtection(keyPath);
      } finally {
        if (descriptor !== undefined) {
          closeSync(descriptor);
        }
        rmSync(temporaryPath, { force: true });
      }
    } catch (error) {
      if (isSafeKeyError(error)) {
        throw error;
      }
      throw new Error("Credential master key could not be created securely.");
    }
  }

  #validateProtection(keyPath: string): void {
    if (this.#platform === "win32") {
      if (
        this.#environment.NODE_ENV !== "test" &&
        this.#environment.COPILOT_IM_GATEWAY_WINDOWS_KEY_ACL !==
        windowsAclAttestation
      ) {
        throw new Error(
          "Windows credential key ACL was not established and verified.",
        );
      }
      const status = lstatSync(keyPath);
      if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) {
        throw new Error("Credential master key must be a regular file.");
      }
      return;
    }
    const directory = path.dirname(keyPath);
    this.#validatePosixDirectory(directory);
    const status = lstatSync(keyPath);
    if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) {
      throw new Error("Credential master key must be a regular file.");
    }
    if ((status.mode & 0o077) !== 0) {
      throw new Error("Credential master key permissions must be owner-only.");
    }
    if (typeof process.getuid === "function" && status.uid !== process.getuid()) {
      throw new Error("Credential master key must be owned by the current user.");
    }
  }

  #validatePosixDirectory(directory: string): void {
    const status = lstatSync(directory);
    if (
      !status.isDirectory() ||
      status.isSymbolicLink() ||
      (status.mode & 0o077) !== 0
    ) {
      throw new Error(
        "Credential key directory must be an owner-only directory.",
      );
    }
    if (typeof process.getuid === "function" && status.uid !== process.getuid()) {
      throw new Error(
        "Credential key directory must be owned by the current user.",
      );
    }
  }
}

export function validateKey(key: Buffer): Buffer {
  if (key.byteLength !== keyBytes) {
    throw new Error("Credential master key has an invalid length.");
  }
  return key;
}

function isNodeError(error: unknown, code: string): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}

function isSafeKeyError(error: unknown): error is Error {
  return (
    error instanceof Error &&
    (error.message.startsWith("Credential ") ||
      error.message.startsWith("Windows credential "))
  );
}

export const masterKeyLength = keyBytes;
export const windowsKeyAclAttestation = windowsAclAttestation;
