import { randomBytes } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  openSync,
  renameSync,
  rmSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AesGcmSecretCipher } from "../core/secret-state.js";
import { resolveGatewayPaths } from "./auth.js";
import {
  FileMasterKeyStorage,
  keyId,
  loadOrCreateMasterKey,
  resolveMasterKeyPaths,
  validateKey,
  writeRotationJournal,
} from "./master-key.js";
import { GatewayStore } from "./store.js";

export function rotateCredentialMasterKey(
  dataDirectory: string,
  environment: NodeJS.ProcessEnv = process.env,
): number {
  const gatewayPaths = resolveGatewayPaths({
    ...environment,
    COPILOT_IM_GATEWAY_DATA_DIR: dataDirectory,
  });
  const paths = resolveMasterKeyPaths(gatewayPaths.dataDirectory);
  const storage = new FileMasterKeyStorage(process.platform, environment);
  const currentKey = loadOrCreateMasterKey({
    keyPath: paths.keyPath,
    databasePath: gatewayPaths.databasePath,
    environment,
  });
  let nextKey = storage.read(paths.nextKeyPath);
  if (nextKey === undefined) {
    nextKey = randomBytes(32);
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
    writeRotationJournal(paths.rotationPath, journal);
    store = new GatewayStore(gatewayPaths.databasePath, {
      secretKey: currentKey,
    });
    const rotated = store.rotateSecrets(new AesGcmSecretCipher(nextKey));
    store.close();
    store = undefined;
    renameSync(paths.keyPath, paths.previousKeyPath);
    renameSync(paths.nextKeyPath, paths.keyPath);
    if (process.platform !== "win32") {
      const directoryDescriptor = openSync(path.dirname(paths.keyPath), "r");
      try {
        fsyncSync(directoryDescriptor);
      } finally {
        closeSync(directoryDescriptor);
      }
    }
    rmSync(paths.previousKeyPath, { force: true });
    rmSync(paths.rotationPath);
    return rotated;
  } finally {
    store?.close();
    currentKey.fill(0);
    nextKey.fill(0);
  }
}

function run(): void {
  const [operation, dataDirectory, ...extra] = process.argv.slice(2);
  if (
    operation !== "rotate-credential-key" ||
    dataDirectory === undefined ||
    extra.length !== 0
  ) {
    throw new Error(
      "Usage: maintenance rotate-credential-key <gateway-data-directory>",
    );
  }
  rotateCredentialMasterKey(path.resolve(dataDirectory));
  console.error("Credential master key rotation completed.");
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
