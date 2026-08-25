import { createHash } from "node:crypto";

export type ChannelId = string;
export type ConversationId = string;
export type SenderId = string;
export type AccountId = string;
export type RouteKey = string & { readonly __routeKey: unique symbol };

export const localTenantId = "local" as const;
export type TenantId = typeof localTenantId;

export interface ChannelAccountIdentity {
  tenantId: TenantId;
  channelId: ChannelId;
  accountId: AccountId;
}

export interface RouteIdentity extends ChannelAccountIdentity {
  conversationId: ConversationId;
  senderId: SenderId;
}

export function canonicalizeIdentityComponents(
  components: readonly string[],
): string {
  return components
    .map((component) => `${Buffer.byteLength(component, "utf8")}:${component}`)
    .join("");
}

export function toRouteKey(identity: RouteIdentity): RouteKey {
  const canonical = canonicalizeIdentityComponents([
    identity.tenantId,
    identity.channelId,
    identity.accountId,
    identity.conversationId,
    identity.senderId,
  ]);
  return createHash("sha256").update(canonical, "utf8").digest("hex") as RouteKey;
}

export interface InboundAttachment {
  id: string;
  mediaType: string;
  sizeBytes?: number;
  fileName?: string;
}

export interface ImInboundMessage {
  tenantId: TenantId;
  channelId: ChannelId;
  accountId: AccountId;
  conversationId: ConversationId;
  messageId: string;
  senderId: SenderId;
  receivedAt: string;
  text: string;
  attachments: InboundAttachment[];
  replyToMessageId?: string;
}

export interface ImOutboundMessage {
  tenantId: TenantId;
  channelId: ChannelId;
  accountId: AccountId;
  conversationId: ConversationId;
  senderId: SenderId;
  correlationId: string;
  text: string;
  format: "plain";
  final: boolean;
}

export type ChannelHealth =
  | { state: "stopped" }
  | { state: "starting"; since: string }
  | { state: "awaiting_login"; since: string; qrCodeUrl?: string }
  | { state: "ready"; since: string; accountLabel?: string }
  | { state: "degraded"; since: string; errorCode: string }
  | { state: "failed"; since: string; errorCode: string };

export interface ChannelContext {
  onInbound(envelope: MinimalInboundEnvelope): Promise<void>;
  onHealth(channelId: ChannelId, health: ChannelHealth): Promise<void>;
}

export interface MinimalInboundEnvelope {
  identity: RouteIdentity;
  messageId: string;
  receivedAt: string;
  materialize(): Promise<ImInboundMessage>;
}

export function deferInboundMessage(
  message: ImInboundMessage,
): MinimalInboundEnvelope {
  return {
    identity: {
      tenantId: message.tenantId,
      channelId: message.channelId,
      accountId: message.accountId,
      conversationId: message.conversationId,
      senderId: message.senderId,
    },
    messageId: message.messageId,
    receivedAt: message.receivedAt,
    materialize: async () => message,
  };
}

export interface ImChannelAdapter {
  readonly id: ChannelId;
  readonly kind: string;
  start(context: ChannelContext): Promise<void>;
  stop(): Promise<void>;
  getHealth(): ChannelHealth;
  send(message: ImOutboundMessage): Promise<void>;
}

export interface ChannelLoginSnapshot {
  state:
    | "not_started"
    | "waiting"
    | "scanned"
    | "verification_required"
    | "confirmed"
    | "expired"
    | "blocked";
  qrCodeUrl?: string;
  accountId?: string;
  userId?: string;
}

export interface LoginCapableChannelAdapter extends ImChannelAdapter {
  startLogin(): Promise<ChannelLoginSnapshot>;
  pollLogin(verifyCode?: string): Promise<ChannelLoginSnapshot>;
}

export function isLoginCapableChannel(
  adapter: ImChannelAdapter,
): adapter is LoginCapableChannelAdapter {
  return (
    "startLogin" in adapter &&
    typeof adapter.startLogin === "function" &&
    "pollLogin" in adapter &&
    typeof adapter.pollLogin === "function"
  );
}

export interface SessionBinding {
  routeKey: RouteKey;
  tenantId: TenantId;
  channelId: ChannelId;
  accountId: AccountId;
  conversationId: ConversationId;
  senderId: SenderId;
  sessionId: string;
  workspaceAlias: string;
  createdAt: string;
  updatedAt: string;
}
