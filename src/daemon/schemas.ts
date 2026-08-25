import { z } from "zod";
import { isWellFormedUnicode } from "../core/contracts.js";

const identifier = z
  .string()
  .min(1)
  .max(200)
  .refine(isWellFormedUnicode, "Identifier must be well-formed Unicode.")
  .refine(
    (value) => !/[\p{Cc}\p{Z}]/u.test(value),
    "Identifier must not contain control or separator characters.",
  );

const tenantId = z.literal("local").default("local");
const routeIdentity = z.object({
  tenantId,
  channelId: identifier,
  accountId: identifier,
  conversationId: identifier,
  senderId: identifier,
});

export const v2InboundMessageSchema = z.object({
  tenantId,
  channelId: identifier,
  accountId: identifier,
  conversationId: identifier,
  messageId: identifier,
  senderId: identifier,
  receivedAt: z.iso.datetime(),
  text: z.string().max(16_000),
  attachments: z
    .array(
      z.object({
        id: identifier,
        mediaType: z.string().min(1).max(200),
        sizeBytes: z.number().int().nonnegative().optional(),
        fileName: z.string().min(1).max(255).optional(),
      }),
    )
    .max(8),
  replyToMessageId: identifier.optional(),
});

export const v2LeaseRequestSchema = z.object({
  sessionId: identifier,
  leaseSeconds: z.number().int().min(10).max(300).default(60),
});

export const v2CompleteMessageSchema = z.object({
  leaseId: z.uuid(),
  outcome: z.enum(["completed", "failed"]),
  errorCode: identifier.optional(),
  retryable: z.boolean().default(false),
});

export const v2OutboundMessageSchema = z.object({
  tenantId,
  channelId: identifier,
  accountId: identifier,
  conversationId: identifier,
  senderId: identifier,
  correlationId: identifier,
  text: z.string().max(64_000),
});

export const v2BindingSchema = z.object({
  tenantId,
  channelId: identifier,
  accountId: identifier,
  conversationId: identifier,
  senderId: identifier,
  sessionId: identifier,
  workspaceAlias: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z][a-z0-9-]*$/),
});

const workspaceAliasShape = {
  alias: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z][a-z0-9-]*$/),
  path: z.string().min(1).max(2048),
  classification: z.enum(["personal", "work"]).default("personal"),
} as const;

export const legacyV1WorkspaceAliasSchema = z.object(workspaceAliasShape);
export const v2WorkspaceAliasSchema = z.object(workspaceAliasShape);

export const v2AllowedSenderSchema = z.object({
  tenantId,
  channelId: identifier,
  accountId: identifier,
  senderId: identifier,
  displayName: z.string().min(1).max(200).optional(),
});

export const v2ApprovalRequestSchema = z.object({
  requestId: identifier,
  identity: routeIdentity.extend({ sessionId: identifier }),
  scope: z.object({
    kind: identifier,
    summary: z
      .string()
      .min(1)
      .max(2000)
      .refine(isWellFormedUnicode, "Summary must be well-formed Unicode."),
    paths: z
      .array(
        z
          .string()
          .max(2048)
          .refine(isWellFormedUnicode, "Path must be well-formed Unicode."),
      )
      .max(20),
    hosts: z
      .array(
        z
          .string()
          .max(255)
          .refine(isWellFormedUnicode, "Host must be well-formed Unicode."),
      )
      .max(20),
    commands: z
      .array(
        z
          .string()
          .max(1000)
          .refine(isWellFormedUnicode, "Command must be well-formed Unicode."),
      )
      .max(20),
  }),
  ttlSeconds: z.number().int().min(30).max(600).default(300),
});

export const v2ApprovalDecisionSchema = z.object({
  nonce: z.string().min(16).max(200),
  decision: z.enum(["approved", "denied"]),
  identity: routeIdentity.extend({ sessionId: identifier }),
});

export const v2ApprovalConsumeSchema = z.object({
  requestId: identifier,
  identity: routeIdentity.extend({ sessionId: identifier }),
  operationDigest: z.string().length(64).regex(/^[a-f0-9]+$/),
});

export const v2AdminApprovalDecisionSchema = z.object({
  requestId: identifier,
  decision: z.enum(["approved", "denied"]),
});

const loginPollShape = {
  verifyCode: z
    .string()
    .min(1)
    .max(20)
    .regex(/^[0-9]+$/)
    .optional(),
} as const;

export const legacyV1LoginPollSchema = z.object(loginPollShape);
export const v2LoginPollSchema = z.object(loginPollShape);
