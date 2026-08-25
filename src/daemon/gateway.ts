import type {
  ChannelContext,
  ChannelHealth,
  ImChannelAdapter,
  ImInboundMessage,
  LoginCapableChannelAdapter,
  MinimalInboundEnvelope,
  RouteIdentity,
} from "../core/contracts.js";
import { isLoginCapableChannel, toRouteKey } from "../core/contracts.js";
import { GatewayError, gatewayErrorCodes } from "../core/errors.js";
import {
  chunkOutboundText,
  createApprovalNonce,
  type Clock,
  type PermissionScope,
  type RemoteIdentity,
  systemClock,
} from "../core/security.js";
import type {
  AdmissionResult,
  ApprovalRecord,
  GatewayStore,
  LeasedInboundMessage,
  ReservedAdmissionResult,
} from "./store.js";

export class GatewayService implements ChannelContext {
  readonly #adapters = new Map<string, ImChannelAdapter>();
  readonly #health = new Map<string, ChannelHealth>();

  constructor(
    readonly store: GatewayStore,
    private readonly clock: Clock = systemClock,
  ) {}

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
    await this.#settleChannelLifecycle(
      (adapter) => adapter.start(this),
      "Gateway channel startup failed.",
    );
  }

  async stopChannels(): Promise<void> {
    await this.#settleChannelLifecycle(
      (adapter) => adapter.stop(),
      "Gateway channel shutdown failed.",
    );
  }

  async #settleChannelLifecycle(
    operation: (adapter: ImChannelAdapter) => Promise<void>,
    failureMessage: string,
  ): Promise<void> {
    const adapters = [...this.#adapters.values()];
    const results = await Promise.allSettled(
      adapters.map((adapter) => Promise.resolve().then(() => operation(adapter))),
    );
    const failures: unknown[] = [];
    for (const result of results) {
      if (result.status === "rejected") {
        failures.push(result.reason);
      }
    }
    for (const adapter of adapters) {
      try {
        this.#health.set(adapter.id, adapter.getHealth());
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length === 1 && failures[0] instanceof Error) {
      throw failures[0];
    }
    if (failures.length > 0) {
      throw new AggregateError(failures, failureMessage);
    }
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

  async onInbound(envelope: MinimalInboundEnvelope): Promise<void> {
    const now = this.clock.now().toISOString();
    const reservation = this.store.reserveInbound(envelope, now);
    this.#throwAdmissionError(reservation);
    if (reservation.disposition === "duplicate") {
      return;
    }

    let message: ImInboundMessage;
    try {
      message = await envelope.materialize();
      this.#validateMaterializedEnvelope(envelope, message);
      const command = parseApprovalCommand(message.text);
      if (command === undefined) {
        this.store.finalizeInbound(
          reservation,
          message,
          this.clock.now().toISOString(),
        );
      } else {
        this.store.finalizeApprovalCommand(
          reservation,
          message,
          command.nonce,
          command.decision,
          this.clock.now().toISOString(),
        );
      }
    } catch (error) {
      const retryableReservationConflict =
        error instanceof GatewayError &&
        error.code === gatewayErrorCodes.conflict &&
        error.retryable;
      if (!retryableReservationConflict) {
        try {
          this.store.failMaterialization(
            reservation,
            envelope.messageId,
            this.clock.now().toISOString(),
          );
        } catch (finalizationError) {
          if (
            !(
              finalizationError instanceof GatewayError &&
              finalizationError.code === gatewayErrorCodes.conflict
            )
          ) {
            throw finalizationError;
          }
        }
      }
      throw error;
    }
  }

  #throwAdmissionError(
    admission: AdmissionResult,
  ): asserts admission is ReservedAdmissionResult | Extract<
    AdmissionResult,
    { disposition: "duplicate" }
  > {
    if (admission.disposition === "in_progress") {
      throw new GatewayError({
        code: gatewayErrorCodes.messageAdmissionPending,
        message: "Inbound message admission is still being materialized.",
        status: 409,
        retryable: true,
      });
    }
    const disposition =
      admission.disposition === "duplicate"
        ? admission.previousDisposition
        : admission.disposition;
    if (disposition === "denied") {
      throw new GatewayError({
        code: gatewayErrorCodes.senderDenied,
        message: "Sender is not paired with this gateway.",
        status: 403,
      });
    }
    if (disposition === "route_denied") {
      throw new GatewayError({
        code: gatewayErrorCodes.workspaceDenied,
        message:
          "Conversation is not bound to an authorized personal workspace.",
        status: 403,
      });
    }
    if (disposition === "rate_limited") {
      throw new GatewayError({
        code: gatewayErrorCodes.rateLimited,
        message: "Message rate limit exceeded.",
        status: 429,
        retryable: false,
      });
    }
    if (disposition === "capacity_rejected") {
      throw new GatewayError({
        code: gatewayErrorCodes.capacityExceeded,
        message: "Gateway pending-message capacity is full.",
        status: 503,
        retryable: false,
      });
    }
  }

  #validateMaterializedEnvelope(
    envelope: MinimalInboundEnvelope,
    message: ImInboundMessage,
  ): void {
    if (
      message.messageId !== envelope.messageId ||
      message.receivedAt !== envelope.receivedAt ||
      toRouteKey(message) !== toRouteKey(envelope.identity)
    ) {
      throw new GatewayError({
        code: gatewayErrorCodes.invalidInput,
        message: "Materialized message identity does not match its envelope.",
        status: 400,
      });
    }
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

  completeInbound(input: {
    id: number;
    leaseId: string;
    outcome: "completed" | "failed";
    errorCode?: string;
    retryable: boolean;
  }): void {
    this.store.completeInbound(
      input.id,
      input.leaseId,
      input.outcome,
      input.errorCode,
      input.retryable,
      this.clock.now().toISOString(),
    );
  }

  async sendOutbound(
    input: RouteIdentity & {
      correlationId: string;
      text: string;
    },
  ): Promise<number> {
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
        tenantId: input.tenantId,
        channelId: input.channelId,
        accountId: input.accountId,
        conversationId: input.conversationId,
        senderId: input.senderId,
        correlationId: `${input.correlationId}-${index + 1}`,
        text,
        format: "plain",
        final: index === chunks.length - 1,
      });
    }
    this.store.appendAudit({
      createdAt: this.clock.now().toISOString(),
      eventType: "outbound.sent",
      actor: "copilot-extension",
      routeKey: toRouteKey(input),
      details: { chunks: chunks.length },
    });
    return chunks.length;
  }

  createApproval(input: {
    requestId: string;
    identity: RemoteIdentity;
    scope: PermissionScope;
    ttlSeconds: number;
  }): { nonce: string; expiresAt: string; operationDigest: string } {
    const nonce = createApprovalNonce();
    const now = this.clock.now();
    const expiresAt = new Date(
      now.getTime() + input.ttlSeconds * 1000,
    ).toISOString();
    const result = this.store.createApproval({
      ...input,
      nonce,
      expiresAt,
      now: now.toISOString(),
    });
    return { nonce, expiresAt, operationDigest: result.operationDigest };
  }

  decideApproval(input: {
    nonce: string;
    identity: RemoteIdentity;
    decision: "approved" | "denied";
  }): ApprovalRecord {
    return this.store.decideApproval({
      ...input,
      now: this.clock.now().toISOString(),
    });
  }

  getStatus(): {
    channels: Array<{
      id: string;
      kind: string;
      health: ChannelHealth;
      login?: { accountId: string; userId?: string };
    }>;
    bindings: ReturnType<GatewayStore["listBindings"]>;
    workspaceAliases: ReturnType<GatewayStore["listWorkspaceAliases"]>;
    allowedSenders: ReturnType<GatewayStore["listAllowedSenders"]>;
    pendingApprovals: ApprovalRecord[];
  } {
    const activeAccounts = this.store.listActiveChannelAccounts();
    return {
      channels: [...this.#adapters.values()].map((adapter) => {
        const account = activeAccounts.find(
          (candidate) => candidate.channelId === adapter.id,
        );
        return {
          id: adapter.id,
          kind: adapter.kind,
          health: this.#health.get(adapter.id) ?? adapter.getHealth(),
          ...(account === undefined
            ? {}
            : {
                login: {
                  accountId: account.accountId,
                  ...(account.userId === undefined
                    ? {}
                    : { userId: account.userId }),
                },
              }),
        };
      }),
      bindings: this.store.listBindings(),
      workspaceAliases: this.store.listWorkspaceAliases(),
      allowedSenders: this.store.listAllowedSenders(),
      pendingApprovals: this.store.listPendingApprovals(
        this.clock.now().toISOString(),
      ),
    };
  }
}

function parseApprovalCommand(
  text: string,
): { nonce: string; decision: "approved" | "denied" } | undefined {
  const match = /^\/(approve|deny)\s+([A-Za-z0-9_-]{16,200})\s*$/i.exec(
    text.trim(),
  );
  const command = match?.[1]?.toLowerCase();
  const nonce = match?.[2];
  if (nonce === undefined || command === undefined) {
    return undefined;
  }
  return {
    nonce,
    decision: command === "approve" ? "approved" : "denied",
  };
}
