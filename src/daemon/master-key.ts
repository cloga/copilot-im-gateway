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

export interface LegacyRotationJournal {
  version: 1;
  currentKeyId: string;
  nextKeyId: string;
}

export interface RotationJournalV2 {
  version: 2;
  currentKeyId: string;
  nextKeyId: string;
  retirementMarker: string;
  retirementKeyId: string;
  retirementState: "prepared" | "wiping" | "rollback-wiping";
}

export type RotationJournal = LegacyRotationJournal | RotationJournalV2;

export interface RotationDurability {
  writeJournal(rotationPath: string, journal: RotationJournal): void;
  rename(sourcePath: string, destinationPath: string): void;
  remove(filePath: string): void;
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
      new FileRotationDurability(platform),
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

export function recoverInterruptedRotation(
  paths: MasterKeyPaths,
  databasePath: string,
  storage: MasterKeyStorage,
  durability: RotationDurability = new FileRotationDurability(),
): void {
  if (!existsSync(paths.rotationPath)) {
    return;
  }
  const journal = parseRotationJournal(
    readFileSync(paths.rotationPath, "utf8"),
  );
  if (journal.version === 2) {
    recoverVersionTwoRotation(
      paths,
      databasePath,
      storage,
      durability,
      journal,
    );
    return;
  }
  const databaseKeyId = readDatabaseCredentialKeyId(databasePath);
  const current = storage.read(paths.keyPath);
  const next = storage.read(paths.nextKeyPath);
  const previous = storage.read(paths.previousKeyPath);
  try {
    const currentId = current === undefined ? undefined : keyId(current);
    const nextId = next === undefined ? undefined : keyId(next);
    const previousId = previous === undefined ? undefined : keyId(previous);
    if (databaseKeyId === journal.currentKeyId) {
      if (
        currentId !== journal.currentKeyId ||
        previousId !== undefined ||
        (nextId !== undefined && nextId !== journal.nextKeyId)
      ) {
        throw new Error(
          "Credential rotation recovery found an invalid rollback state.",
        );
      }

      if (nextId !== undefined) {
        durability.remove(paths.nextKeyPath);
      }
      durability.remove(paths.rotationPath);
      return;
    }
    if (databaseKeyId !== journal.nextKeyId) {
      throw new Error(
        "Credential rotation journal does not match the gateway database.",
      );
    }
    const beforeSwap =
      currentId === journal.currentKeyId &&
      nextId === journal.nextKeyId &&
      previousId === undefined;
    const betweenRenames =
      currentId === undefined &&
      nextId === journal.nextKeyId &&
      previousId === journal.currentKeyId;
    const afterSwap =
      currentId === journal.nextKeyId &&
      nextId === undefined &&
      previousId === journal.currentKeyId;
    const afterPriorKeyRemoval =
      currentId === journal.nextKeyId &&
      nextId === undefined &&
      previousId === undefined;
    if (
      !beforeSwap &&
      !betweenRenames &&
      !afterSwap &&
      !afterPriorKeyRemoval
    ) {
      throw new Error(
        "Credential rotation recovery found an invalid committed state.",
      );
    }
    if (beforeSwap) {
      durability.rename(paths.keyPath, paths.previousKeyPath);
    }
    if (beforeSwap || betweenRenames) {
      durability.rename(paths.nextKeyPath, paths.keyPath);
    }
    if (beforeSwap || betweenRenames || afterSwap) {
      durability.remove(paths.previousKeyPath);
    }
    durability.remove(paths.rotationPath);
  } finally {
    current?.fill(0);
    next?.fill(0);
    previous?.fill(0);
  }
}

function recoverVersionTwoRotation(
  paths: MasterKeyPaths,
  databasePath: string,
  storage: MasterKeyStorage,
  durability: RotationDurability,
  journal: RotationJournalV2,
): void {
  const retirementPath = path.join(
    path.dirname(paths.keyPath),
    journal.retirementMarker,
  );
  const databaseKeyId = readDatabaseCredentialKeyId(databasePath);
  const current = storage.read(paths.keyPath);
  const next = storage.read(paths.nextKeyPath);
  const previous = storage.read(paths.previousKeyPath);
  const retirement = storage.read(retirementPath);
  try {
    const currentId = current === undefined ? undefined : keyId(current);
    const nextId = next === undefined ? undefined : keyId(next);
    const previousId = previous === undefined ? undefined : keyId(previous);
    const retirementId =
      retirement === undefined ? undefined : keyId(retirement);
    if (previousId !== undefined) {
      throw new Error(
        "Credential rotation recovery found an unexpected legacy key path.",
      );
    }
    if (journal.retirementState === "rollback-wiping") {
      if (
        databaseKeyId !== journal.currentKeyId ||
        currentId !== journal.currentKeyId ||
        nextId !== undefined ||
        previousId !== undefined ||
        (retirement !== undefined && retirement.byteLength !== keyBytes)
      ) {
        throw new Error(
          "Credential rotation recovery found an invalid rollback wiping state.",
        );
      }
      return;
    }
    if (journal.retirementState === "wiping") {
      if (
        databaseKeyId !== journal.nextKeyId ||
        currentId !== journal.nextKeyId ||
        nextId !== undefined ||
        (retirement !== undefined && retirement.byteLength !== keyBytes)
      ) {
        throw new Error(
          "Credential rotation recovery found an invalid wiping state.",
        );
      }
      return;
    }
    if (databaseKeyId === journal.currentKeyId) {
      if (
        currentId !== journal.currentKeyId ||
        retirementId !== undefined ||
        (nextId !== undefined && nextId !== journal.nextKeyId)
      ) {
        throw new Error(
          "Credential rotation recovery found an invalid rollback state.",
        );
      }
      if (nextId !== undefined) {
        durability.remove(paths.nextKeyPath);
      }
      durability.remove(paths.rotationPath);
      return;
    }
    if (
      databaseKeyId !== journal.nextKeyId
    ) {
      throw new Error(
        "Credential rotation journal does not match the gateway database.",
      );
    }
    const beforeRetirementMove =
      currentId === journal.currentKeyId &&
      nextId === journal.nextKeyId &&
      retirementId === undefined;
    const betweenRenames =
      currentId === undefined &&
      nextId === journal.nextKeyId &&
      retirementId === journal.retirementKeyId;
    const afterSwap =
      currentId === journal.nextKeyId &&
      nextId === undefined &&
      retirementId === journal.retirementKeyId;
    const afterRetirementRemoval =
      currentId === journal.nextKeyId &&
      nextId === undefined &&
      retirementId === undefined;
    if (
      !beforeRetirementMove &&
      !betweenRenames &&
      !afterSwap &&
      !afterRetirementRemoval
    ) {
      throw new Error(
        "Credential rotation recovery found an invalid committed state.",
      );
    }
    if (beforeRetirementMove) {
      durability.rename(paths.keyPath, retirementPath);
    }
    if (beforeRetirementMove || betweenRenames) {
      durability.rename(paths.nextKeyPath, paths.keyPath);
    }
    if (beforeRetirementMove || betweenRenames || afterSwap) {
      durability.remove(retirementPath);
    }
    durability.remove(paths.rotationPath);
  } finally {
    current?.fill(0);
    next?.fill(0);
    previous?.fill(0);
    retirement?.fill(0);
  }
}

export function writeRotationJournal(
  rotationPath: string,
  journal: RotationJournal,
): void {
  const temporaryPath = `${rotationPath}.create-${process.pid}-${randomBytes(8).toString("hex")}`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporaryPath, "wx", 0o600);
    fchmodSync(descriptor, 0o600);
    writeFileSync(descriptor, `${JSON.stringify(journal)}\n`, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    linkSync(temporaryPath, rotationPath);
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
    rmSync(temporaryPath, { force: true });
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

export function parseRotationJournal(value: string): RotationJournal {
  const parsed: unknown = JSON.parse(value);
  if (isLegacyRotationJournal(parsed)) {
    return parsed;
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    Object.keys(parsed).sort().join(",") !==
      "currentKeyId,nextKeyId,retirementKeyId,retirementMarker,retirementState,version" ||
    !("version" in parsed) ||
    parsed.version !== 2 ||
    !("currentKeyId" in parsed) ||
    typeof parsed.currentKeyId !== "string" ||
    !/^[a-f0-9]{64}$/u.test(parsed.currentKeyId) ||
    !("nextKeyId" in parsed) ||
    typeof parsed.nextKeyId !== "string" ||
    !/^[a-f0-9]{64}$/u.test(parsed.nextKeyId) ||
    parsed.currentKeyId === parsed.nextKeyId ||
    !("retirementKeyId" in parsed) ||
    typeof parsed.retirementKeyId !== "string" ||
    !("retirementMarker" in parsed) ||
    typeof parsed.retirementMarker !== "string" ||
    !("retirementState" in parsed) ||
    (parsed.retirementState !== "prepared" &&
      parsed.retirementState !== "wiping" &&
      parsed.retirementState !== "rollback-wiping") ||
    !validRetirementBinding(
      parsed.currentKeyId,
      parsed.nextKeyId,
      parsed.retirementKeyId,
      parsed.retirementMarker,
      parsed.retirementState,
    )
  ) {
    throw new Error("Credential rotation journal is invalid.");
  }
  return {
    version: 2,
    currentKeyId: parsed.currentKeyId,
    nextKeyId: parsed.nextKeyId,
    retirementMarker: parsed.retirementMarker,
    retirementKeyId: parsed.retirementKeyId,
    retirementState: parsed.retirementState,
  };
}

function isLegacyRotationJournal(
  value: unknown,
): value is LegacyRotationJournal {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") ===
      "currentKeyId,nextKeyId,version" &&
    "version" in value &&
    value.version === 1 &&
    "currentKeyId" in value &&
    typeof value.currentKeyId === "string" &&
    /^[a-f0-9]{64}$/u.test(value.currentKeyId) &&
    "nextKeyId" in value &&
    typeof value.nextKeyId === "string" &&
    /^[a-f0-9]{64}$/u.test(value.nextKeyId) &&
    value.currentKeyId !== value.nextKeyId
  );
}

export function rotationRetirementMarker(currentKeyId: string): string {
  if (!/^[a-f0-9]{64}$/u.test(currentKeyId)) {
    throw new Error("Credential rotation key identity is invalid.");
  }
  return `credential-master-key.retire-${currentKeyId}`;
}

function validRetirementBinding(
  currentKeyId: string,
  nextKeyId: string,
  retirementKeyId: unknown,
  retirementMarker: unknown,
  retirementState: "prepared" | "wiping" | "rollback-wiping",
): boolean {
  if (
    typeof retirementKeyId !== "string" ||
    typeof retirementMarker !== "string"
  ) {
    return false;
  }
  if (retirementState === "rollback-wiping") {
    return (
      retirementKeyId === nextKeyId &&
      retirementMarker === `credential-master-key.abort-${nextKeyId}`
    );
  }
  return (
    retirementKeyId === currentKeyId &&
    retirementMarker === rotationRetirementMarker(currentKeyId)
  );
}

export class FileRotationDurability implements RotationDurability {
  readonly #platform: NodeJS.Platform;

  constructor(platform: NodeJS.Platform = process.platform) {
    this.#platform = platform;
  }

  writeJournal(rotationPath: string, journal: RotationJournal): void {
    this.#requirePosix();
    writeRotationJournal(rotationPath, journal);
    this.#syncParent(rotationPath);
  }

  rename(sourcePath: string, destinationPath: string): void {
    this.#requirePosix();
    if (path.dirname(sourcePath) !== path.dirname(destinationPath)) {
      throw new Error("Credential rotation paths must share one directory.");
    }
    renameSync(sourcePath, destinationPath);
    this.#syncParent(destinationPath);
  }

  remove(filePath: string): void {
    this.#requirePosix();
    rmSync(filePath);
    this.#syncParent(filePath);
  }

  #requirePosix(): void {
    if (this.#platform === "win32") {
      throw new Error(
        "Windows credential rotation requires the bundled durable ACL helper.",
      );
    }
  }

  #syncParent(filePath: string): void {
    const descriptor = openSync(path.dirname(filePath), "r");
    try {
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
  }
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
