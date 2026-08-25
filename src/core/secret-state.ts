import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes as systemRandomBytes,
} from "node:crypto";
import { z } from "zod";
import { canonicalizeIdentityComponents } from "./contracts.js";

const algorithm = "aes-256-gcm";
const envelopeVersion = 1;
const nonceBytes = 12;
const tagBytes = 16;

const secretEnvelopeSchema = z
  .object({
    v: z.literal(envelopeVersion),
    alg: z.literal("A256GCM"),
    kid: z.string().regex(/^[a-f0-9]{64}$/u),
    nonce: z.string().min(1),
    ciphertext: z.string(),
    tag: z.string().min(1),
  })
  .strict();

export interface SecretStateIdentity {
  tenantId: string;
  channelId: string;
  accountId: string;
  stateKey: string;
}

export interface SecretCipher {
  readonly keyId: string;
  encrypt(identity: SecretStateIdentity, value: unknown): string;
  decrypt(identity: SecretStateIdentity, envelope: string): unknown;
  destroy(): void;
}

export interface AesGcmSecretCipherOptions {
  randomBytes?: (size: number) => Buffer;
}

export class SecretStateDecryptionError extends Error {
  constructor() {
    super("Sensitive channel state could not be decrypted.");
    this.name = "SecretStateDecryptionError";
  }
}

export class AesGcmSecretCipher implements SecretCipher {
  readonly keyId: string;
  readonly #key: Buffer;
  readonly #randomBytes: (size: number) => Buffer;
  #destroyed = false;

  constructor(
    key: Uint8Array,
    options: AesGcmSecretCipherOptions = {},
  ) {
    if (key.byteLength !== 32) {
      throw new Error("The credential master key must contain exactly 32 bytes.");
    }
    this.#key = Buffer.from(key);
    this.keyId = createHash("sha256").update(this.#key).digest("hex");
    this.#randomBytes = options.randomBytes ?? systemRandomBytes;
  }

  encrypt(identity: SecretStateIdentity, value: unknown): string {
    this.#assertLive();
    const nonce = this.#randomBytes(nonceBytes);
    if (nonce.byteLength !== nonceBytes) {
      throw new Error("The credential nonce source returned an invalid length.");
    }
    const cipher = createCipheriv(algorithm, this.#key, nonce, {
      authTagLength: tagBytes,
    });
    cipher.setAAD(this.#associatedData(identity));
    const plaintext = Buffer.from(JSON.stringify(value), "utf8");
    try {
      const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
      ]);
      return JSON.stringify({
        v: envelopeVersion,
        alg: "A256GCM",
        kid: this.keyId,
        nonce: nonce.toString("base64url"),
        ciphertext: ciphertext.toString("base64url"),
        tag: cipher.getAuthTag().toString("base64url"),
      });
    } finally {
      plaintext.fill(0);
    }
  }

  decrypt(identity: SecretStateIdentity, envelope: string): unknown {
    this.#assertLive();
    try {
      const parsed = secretEnvelopeSchema.parse(JSON.parse(envelope));
      if (parsed.kid !== this.keyId) {
        throw new SecretStateDecryptionError();
      }
      const nonce = Buffer.from(parsed.nonce, "base64url");
      const ciphertext = Buffer.from(parsed.ciphertext, "base64url");
      const tag = Buffer.from(parsed.tag, "base64url");
      if (nonce.byteLength !== nonceBytes || tag.byteLength !== tagBytes) {
        throw new SecretStateDecryptionError();
      }
      const decipher = createDecipheriv(algorithm, this.#key, nonce, {
        authTagLength: tagBytes,
      });
      decipher.setAAD(this.#associatedData(identity));
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);
      try {
        return JSON.parse(plaintext.toString("utf8")) as unknown;
      } finally {
        plaintext.fill(0);
      }
    } catch (error) {
      if (error instanceof SecretStateDecryptionError) {
        throw error;
      }
      throw new SecretStateDecryptionError();
    }
  }

  destroy(): void {
    if (!this.#destroyed) {
      this.#key.fill(0);
      this.#destroyed = true;
    }
  }

  #associatedData(identity: SecretStateIdentity): Buffer {
    return Buffer.from(
      canonicalizeIdentityComponents([
        "copilot-im-gateway",
        "channel-secret",
        String(envelopeVersion),
        identity.tenantId,
        identity.channelId,
        identity.accountId,
        identity.stateKey,
      ]),
      "utf8",
    );
  }

  #assertLive(): void {
    if (this.#destroyed) {
      throw new Error("The credential cipher has been destroyed.");
    }
  }
}

export const channelSecretEnvelopeVersion = envelopeVersion;
