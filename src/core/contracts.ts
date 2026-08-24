export type ChannelId = string;
export type ConversationId = string;
export type SenderId = string;
export type RouteKey = `${string}:${string}`;

export interface InboundAttachment {
  id: string;
  mediaType: string;
  sizeBytes?: number;
  fileName?: string;
}

export interface ImInboundMessage {
  channelId: ChannelId;
  conversationId: ConversationId;
  messageId: string;
  senderId: SenderId;
  receivedAt: string;
  text: string;
  attachments: InboundAttachment[];
  replyToMessageId?: string;
}

export interface ImOutboundMessage {
  channelId: ChannelId;
  conversationId: ConversationId;
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
  onInbound(message: ImInboundMessage): Promise<void>;
  onHealth(channelId: ChannelId, health: ChannelHealth): Promise<void>;
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
  channelId: ChannelId;
  conversationId: ConversationId;
  sessionId: string;
  workspaceAlias: string;
  createdAt: string;
  updatedAt: string;
}

export function toRouteKey(
  channelId: ChannelId,
  conversationId: ConversationId,
): RouteKey {
  return `${channelId}:${conversationId}`;
}
