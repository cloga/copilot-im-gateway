import type {
  ChannelContext,
  ChannelHealth,
  ImChannelAdapter,
  ImInboundMessage,
  LoginCapableChannelAdapter,
} from "../core/contracts.js";
import { isLoginCapableChannel, toRouteKey } from "../core/contracts.js";
import { GatewayError, gatewayErrorCodes } from "../core/errors.js";
import { KeyedSerialQueue } from "../core/serial-queue.js";
import {
  chunkOutboundText,
  createApprovalNonce,
  type Clock,
  type PermissionScope,
  type RemoteIdentity,
  SlidingWindowRateLimiter,
  systemClock,
} from "../core/security.js";
import type {
  ApprovalRecord,
  GatewayStore,
  LeasedInboundMessage,
} from "./store.js";

export class GatewayService implements ChannelContext {
  readonly #adapters = new Map<string, ImChannelAdapter>();
  readonly #health = new Map<string, ChannelHealth>();
  readonly #queue = new KeyedSerialQueue();
  readonly #rateLimiter: SlidingWindowRateLimiter;

  constructor(
    readonly store: GatewayStore,
    private readonly clock: Clock = systemClock,
  ) {
    this.#rateLimiter = new SlidingWindowRateLimiter(12, 60_000, clock);
  }

  registerChannel(adapter: ImChannelAdapter): void {
    if (this.#adapters.has(adapter.id)) {
      throw new GatewayError({
        code: gatewayErrorCodes.conflict,
        message: `Channel '${adapter.id}' is already registered.`,
        status: 409,
      });
    }
    this.#adapters.set(adapter.id, adapter);
    this.#health.set(adapter.id, adapter.getHealth());
  }

  async startChannels(): Promise<void> {
    await Promise.all(
      [...this.#adapters.values()].map(async (adapter) => {
        await adapter.start(this);
        this.#health.set(adapter.id, adapter.getHealth());
      }),
    );
  }

  async stopChannels(): Promise<void> {
    await Promise.all(
      [...this.#adapters.values()].map(async (adapter) => {
        await adapter.stop();
        this.#health.set(adapter.id, adapter.getHealth());
      }),
    );
  }

  getChannel(id: string): ImChannelAdapter {
    const adapter = this.#adapters.get(id);
    if (adapter === undefined) {
      throw new GatewayError({
        code: gatewayErrorCodes.channelNotFound,
        message: `Channel '${id}' is not registered.`,
        status: 404,
      });
    }
    return adapter;
  }

  getLoginChannel(id: string): LoginCapableChannelAdapter {
    const adapter = this.getChannel(id);
    if (!isLoginCapableChannel(adapter)) {
      throw new GatewayError({
        code: gatewayErrorCodes.conflict,
        message: `Channel '${id}' does not support interactive login.`,
        status: 409,
      });
    }
    return adapter;
  }

  async onHealth(channelId: string, health: ChannelHealth): Promise<void> {
    this.#health.set(channelId, health);
    this.store.appendAudit({
      createdAt: this.clock.now().toISOString(),
      eventType: "channel.health.changed",
      actor: `channel:${channelId}`,
      details: { state: health.state },
    });
  }

  async onInbound(message: ImInboundMessage): Promise<void> {
    const routeKey = toRouteKey(message.channelId, message.conversationId);
    await this.#queue.run(routeKey, async () => {
      this.#rateLimiter.consume(
        `${message.channelId}:${message.senderId}`,
      );
      if (!this.store.isSenderAllowed(message.channelId, message.senderId)) {
        this.store.appendAudit({
          createdAt: this.clock.now().toISOString(),
          eventType: "inbound.sender.denied",
          actor: `sender:${message.senderId}`,
          routeKey,
        });
        throw new GatewayError({
          code: gatewayErrorCodes.senderDenied,
          message: "Sender is not paired with this gateway.",
          status: 403,
        });
      }

      const commandHandled = this.#handleApprovalCommand(message);
      if (commandHandled) {
        return;
      }

      const inserted = this.store.insertInbound(
        message,
        this.clock.now().toISOString(),
      );
      this.store.appendAudit({
        createdAt: this.clock.now().toISOString(),
        eventType: inserted
          ? "inbound.accepted"
          : "inbound.duplicate",
        actor: `sender:${message.senderId}`,
        routeKey,
        details: { messageId: message.messageId },
      });
    });
  }

  #handleApprovalCommand(message: ImInboundMessage): boolean {
    const match = /^\/(approve|deny)\s+([A-Za-z0-9_-]{16,200})\s*$/i.exec(
      message.text.trim(),
    );
    if (match === null) {
      return false;
    }
    const command = match[1]?.toLowerCase();
    const nonce = match[2];
    if (nonce === undefined || command === undefined) {
      return false;
    }
    const bindings = this.store.listBindings();
    const routeKey = toRouteKey(message.channelId, message.conversationId);
    const binding = bindings.find((candidate) => candidate.routeKey === routeKey);
    if (binding === undefined) {
      throw new GatewayError({
        code: gatewayErrorCodes.notFound,
        message: "Conversation is not bound to a Copilot session.",
        status: 404,
      });
    }
    this.decideApproval({
      nonce,
      decision: command === "approve" ? "approved" : "denied",
      identity: {
        channelId: message.channelId,
        conversationId: message.conversationId,
        senderId: message.senderId,
        sessionId: binding.sessionId,
      },
    });
    return true;
  }

  leaseInbound(
    sessionId: string,
    leaseSeconds: number,
  ): LeasedInboundMessage | undefined {
    return this.store.leaseInbound(
      sessionId,
      this.clock.now().toISOString(),
      leaseSeconds,
    );
  }

  async sendOutbound(input: {
    channelId: string;
    conversationId: string;
    correlationId: string;
    text: string;
  }): Promise<number> {
    const adapter = this.#adapters.get(input.channelId);
    if (adapter === undefined) {
      throw new GatewayError({
        code: gatewayErrorCodes.channelNotFound,
        message: `Channel '${input.channelId}' is not registered.`,
        status: 404,
      });
    }
    const chunks = chunkOutboundText(input.text);
    for (const [index, text] of chunks.entries()) {
      await adapter.send({
        channelId: input.channelId,
        conversationId: input.conversationId,
        correlationId: `${input.correlationId}:${index + 1}`,
        text,
        format: "plain",
        final: index === chunks.length - 1,
      });
    }
    this.store.appendAudit({
      createdAt: this.clock.now().toISOString(),
      eventType: "outbound.sent",
      actor: "copilot-extension",
      routeKey: toRouteKey(input.channelId, input.conversationId),
      details: { chunks: chunks.length },
    });
    return chunks.length;
  }

  createApproval(input: {
    requestId: string;
    identity: RemoteIdentity;
    scope: PermissionScope;
    ttlSeconds: number;
  }): { nonce: string; expiresAt: string } {
    const nonce = createApprovalNonce();
    const now = this.clock.now();
    const expiresAt = new Date(
      now.getTime() + input.ttlSeconds * 1000,
    ).toISOString();
    this.store.createApproval({
      ...input,
      nonce,
      expiresAt,
      now: now.toISOString(),
    });
    this.store.appendAudit({
      createdAt: now.toISOString(),
      eventType: "approval.requested",
      actor: "copilot-extension",
      routeKey: toRouteKey(
        input.identity.channelId,
        input.identity.conversationId,
      ),
      details: {
        requestId: input.requestId,
        kind: input.scope.kind,
        expiresAt,
      },
    });
    return { nonce, expiresAt };
  }

  decideApproval(input: {
    nonce: string;
    identity: RemoteIdentity;
    decision: "approved" | "denied";
  }): ApprovalRecord {
    const record = this.store.decideApproval({
      ...input,
      now: this.clock.now().toISOString(),
    });
    this.store.appendAudit({
      createdAt: this.clock.now().toISOString(),
      eventType: `approval.${input.decision}`,
      actor: `sender:${input.identity.senderId}`,
      routeKey: toRouteKey(
        input.identity.channelId,
        input.identity.conversationId,
      ),
      details: { requestId: record.requestId },
    });
    return record;
  }

  getStatus(): {
    channels: Array<{ id: string; kind: string; health: ChannelHealth }>;
    bindings: ReturnType<GatewayStore["listBindings"]>;
    workspaceAliases: ReturnType<GatewayStore["listWorkspaceAliases"]>;
    allowedSenders: ReturnType<GatewayStore["listAllowedSenders"]>;
    pendingApprovals: ApprovalRecord[];
  } {
    return {
      channels: [...this.#adapters.values()].map((adapter) => ({
        id: adapter.id,
        kind: adapter.kind,
        health: this.#health.get(adapter.id) ?? adapter.getHealth(),
      })),
      bindings: this.store.listBindings(),
      workspaceAliases: this.store.listWorkspaceAliases(),
      allowedSenders: this.store.listAllowedSenders(),
      pendingApprovals: this.store.listPendingApprovals(
        this.clock.now().toISOString(),
      ),
    };
  }
}
