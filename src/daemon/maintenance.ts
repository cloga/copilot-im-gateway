import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AesGcmSecretCipher } from "../core/secret-state.js";
import { resolveGatewayPaths } from "./auth.js";
import {
  FileMasterKeyStorage,
  FileRotationDurability,
  keyId,
  loadOrCreateMasterKey,
  parseRotationJournal,
  readDatabaseCredentialKeyId,
  recoverInterruptedRotation,
  resolveMasterKeyPaths,
  validateKey,
  type MasterKeyStorage,
  type RotationDurability,
} from "./master-key.js";
import { GatewayStore } from "./store.js";

export interface RotationDependencies {
  platform?: NodeJS.Platform;
  storage?: MasterKeyStorage;
  durability?: RotationDurability;
  createRandomKey?: () => Buffer;
}

export function rotateCredentialMasterKey(
  dataDirectory: string,
  environment: NodeJS.ProcessEnv = process.env,
  dependencies: RotationDependencies = {},
): number {
  const gatewayPaths = resolveGatewayPaths({
    ...environment,
    COPILOT_IM_GATEWAY_DATA_DIR: dataDirectory,
  });
  const paths = resolveMasterKeyPaths(gatewayPaths.dataDirectory);
  const platform = dependencies.platform ?? process.platform;
  const storage =
    dependencies.storage ?? new FileMasterKeyStorage(platform, environment);
  const durability =
    dependencies.durability ?? new FileRotationDurability(platform);
  const recovering = existsSync(paths.rotationPath);
  recoverInterruptedRotation(
    paths,
    gatewayPaths.databasePath,
    storage,
    durability,
  );
  if (recovering) {
    return 0;
  }
  const currentKey = loadOrCreateMasterKey({
    keyPath: paths.keyPath,
    databasePath: gatewayPaths.databasePath,
    environment,
    platform,
    storage,
  });
  let nextKey = storage.read(paths.nextKeyPath);
  if (nextKey === undefined) {
    nextKey = (dependencies.createRandomKey ?? (() => randomBytes(32)))();
    storage.create(paths.nextKeyPath, nextKey);
  }
  validateKey(nextKey);
  const journal = {
    version: 1 as const,
    currentKeyId: keyId(currentKey),
    nextKeyId: keyId(nextKey),
  };
  let store: GatewayStore | undefined;
  try {
    durability.writeJournal(paths.rotationPath, journal);
    store = new GatewayStore(gatewayPaths.databasePath, {
      secretKey: currentKey,
    });
    const rotated = store.rotateSecrets(new AesGcmSecretCipher(nextKey));
    store.close();
    store = undefined;
    durability.rename(paths.keyPath, paths.previousKeyPath);
    durability.rename(paths.nextKeyPath, paths.keyPath);
    durability.remove(paths.previousKeyPath);
    durability.remove(paths.rotationPath);
    return rotated;
  } finally {
    store?.close();
    currentKey.fill(0);
    nextKey.fill(0);
  }
}

export function reencryptCredentialMasterKey(
  dataDirectory: string,
  environment: NodeJS.ProcessEnv = process.env,
): number {
  const gatewayPaths = resolveGatewayPaths({
    ...environment,
    COPILOT_IM_GATEWAY_DATA_DIR: dataDirectory,
  });
  const paths = resolveMasterKeyPaths(gatewayPaths.dataDirectory);
  const storage = new FileMasterKeyStorage(process.platform, environment);
  const journal = parseRotationJournal(
    readFileSync(paths.rotationPath, "utf8"),
  );
  const currentKey = validateKey(
    storage.read(paths.keyPath) ??
      (() => {
        throw new Error("Credential rotation current key is missing.");
      })(),
  );
  const nextKey = validateKey(
    storage.read(paths.nextKeyPath) ??
      (() => {
        throw new Error("Credential rotation next key is missing.");
      })(),
  );
  let store: GatewayStore | undefined;
  try {
    if (
      keyId(currentKey) !== journal.currentKeyId ||
      keyId(nextKey) !== journal.nextKeyId ||
      readDatabaseCredentialKeyId(gatewayPaths.databasePath) !==
        journal.currentKeyId
    ) {
      throw new Error(
        "Credential rotation inputs do not match the durable journal.",
      );
    }
    store = new GatewayStore(gatewayPaths.databasePath, {
      secretKey: currentKey,
    });
    const rotated = store.rotateSecrets(new AesGcmSecretCipher(nextKey));
    store.close();
    store = undefined;
    return rotated;
  } finally {
    store?.close();
    currentKey.fill(0);
    nextKey.fill(0);
  }
}

export function classifyCredentialKeyRotation(
  dataDirectory: string,
  environment: NodeJS.ProcessEnv = process.env,
): "current" | "next" {
  const gatewayPaths = resolveGatewayPaths({
    ...environment,
    COPILOT_IM_GATEWAY_DATA_DIR: dataDirectory,
  });
  const paths = resolveMasterKeyPaths(gatewayPaths.dataDirectory);
  const journal = parseRotationJournal(
    readFileSync(paths.rotationPath, "utf8"),
  );
  const databaseKeyId = readDatabaseCredentialKeyId(gatewayPaths.databasePath);
  if (databaseKeyId === journal.currentKeyId) {
    return "current";
  }
  if (databaseKeyId === journal.nextKeyId) {
    return "next";
  }
  throw new Error("Credential rotation journal does not match the database.");
}

function run(): void {
  const [operation, dataDirectory, ...extra] = process.argv.slice(2);
  if (
    (operation !== "rotate-credential-key" &&
      operation !== "reencrypt-credential-key" &&
      operation !== "classify-credential-key-rotation") ||
    dataDirectory === undefined ||
    extra.length !== 0
  ) {
    throw new Error(
      "Usage: maintenance <rotate-credential-key|reencrypt-credential-key|classify-credential-key-rotation> <gateway-data-directory>",
    );
  }
  const resolvedDirectory = path.resolve(dataDirectory);
  if (operation === "rotate-credential-key") {
    rotateCredentialMasterKey(resolvedDirectory);
    console.error("Credential master key rotation completed.");
  } else if (operation === "reencrypt-credential-key") {
    reencryptCredentialMasterKey(resolvedDirectory);
  } else {
    process.exitCode =
      classifyCredentialKeyRotation(resolvedDirectory) === "current" ? 20 : 21;
  }
}

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    run();
  } catch {
    console.error("Credential master key maintenance failed safely.");
    process.exitCode = 1;
  }
}
