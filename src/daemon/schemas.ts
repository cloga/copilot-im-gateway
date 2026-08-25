import { z } from "zod";

const identifier = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9._:@/-]+$/);

const tenantId = z.literal("local").default("local");
const routeIdentity = z.object({
  tenantId,
  channelId: identifier,
  accountId: identifier,
  conversationId: identifier,
  senderId: identifier,
});

export const inboundMessageSchema = z.object({
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

export const leaseRequestSchema = z.object({
  sessionId: identifier,
  leaseSeconds: z.number().int().min(10).max(300).default(60),
});

export const completeMessageSchema = z.object({
  leaseId: z.uuid(),
  outcome: z.enum(["completed", "failed"]),
  errorCode: identifier.optional(),
  retryable: z.boolean().default(false),
});

export const outboundMessageSchema = z.object({
  tenantId,
  channelId: identifier,
  accountId: identifier,
  conversationId: identifier,
  senderId: identifier,
  correlationId: identifier,
  text: z.string().max(64_000),
});

export const bindingSchema = z.object({
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

export const workspaceAliasSchema = z.object({
  alias: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z][a-z0-9-]*$/),
  path: z.string().min(1).max(2048),
  classification: z.enum(["personal", "work"]).default("personal"),
});

export const allowedSenderSchema = z.object({
  tenantId,
  channelId: identifier,
  accountId: identifier,
  senderId: identifier,
  displayName: z.string().min(1).max(200).optional(),
});

export const approvalRequestSchema = z.object({
  requestId: identifier,
  identity: routeIdentity.extend({ sessionId: identifier }),
  scope: z.object({
    kind: identifier,
    summary: z.string().min(1).max(2000),
    paths: z.array(z.string().max(2048)).max(20),
    hosts: z.array(z.string().max(255)).max(20),
    commands: z.array(z.string().max(1000)).max(20),
  }),
  ttlSeconds: z.number().int().min(30).max(600).default(300),
});

export const approvalDecisionSchema = z.object({
  nonce: z.string().min(16).max(200),
  decision: z.enum(["approved", "denied"]),
  identity: routeIdentity.extend({ sessionId: identifier }),
});

export const approvalConsumeSchema = z.object({
  requestId: identifier,
  identity: routeIdentity.extend({ sessionId: identifier }),
  operationDigest: z.string().length(64).regex(/^[a-f0-9]+$/),
});

export const adminApprovalDecisionSchema = z.object({
  requestId: identifier,
  decision: z.enum(["approved", "denied"]),
});

export const loginPollSchema = z.object({
  verifyCode: z
    .string()
    .min(1)
    .max(20)
    .regex(/^[0-9]+$/)
    .optional(),
});
