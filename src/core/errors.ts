export const gatewayErrorCodes = {
  approvalExpired: "APPROVAL_EXPIRED",
  approvalMismatch: "APPROVAL_IDENTITY_MISMATCH",
  approvalNotFound: "APPROVAL_NOT_FOUND",
  approvalReplayed: "APPROVAL_ALREADY_CONSUMED",
  authenticationRequired: "AUTHENTICATION_REQUIRED",
  channelNotFound: "CHANNEL_NOT_FOUND",
  capacityExceeded: "PENDING_CAPACITY_EXCEEDED",
  conflict: "STATE_CONFLICT",
  internal: "INTERNAL_ERROR",
  invalidInput: "INVALID_INPUT",
  messageAdmissionPending: "MESSAGE_ADMISSION_IN_PROGRESS",
  messageDuplicate: "MESSAGE_DUPLICATE",
  messageNotFound: "MESSAGE_NOT_FOUND",
  migrationRequired: "MIGRATION_AMBIGUOUS",
  ownershipConflict: "DATABASE_OWNERSHIP_CONFLICT",
  notFound: "NOT_FOUND",
  rateLimited: "RATE_LIMITED",
  senderDenied: "SENDER_NOT_ALLOWED",
  upgradeRequired: "UPGRADE_REQUIRED",
  workspaceDenied: "WORKSPACE_NOT_ALLOWED",
} as const;

export type GatewayErrorCode =
  (typeof gatewayErrorCodes)[keyof typeof gatewayErrorCodes];

export class GatewayError extends Error {
  readonly code: GatewayErrorCode;
  readonly retryable: boolean;
  readonly status: number;
  readonly details: Readonly<Record<string, unknown>> | undefined;

  constructor(options: {
    code: GatewayErrorCode;
    message: string;
    status: number;
    retryable?: boolean;
    details?: Readonly<Record<string, unknown>>;
  }) {
    super(options.message);
    this.name = "GatewayError";
    this.code = options.code;
    this.status = options.status;
    this.retryable = options.retryable ?? false;
    this.details = options.details;
  }
}

export interface ErrorEnvelope {
  error: {
    code: GatewayErrorCode;
    message: string;
    retryable: boolean;
    details?: Readonly<Record<string, unknown>>;
  };
  requestId: string;
}

export function toErrorEnvelope(
  error: GatewayError,
  requestId: string,
): ErrorEnvelope {
  return {
    error: {
      code: error.code,
      message: error.message,
      retryable: error.retryable,
      ...(error.details === undefined ? {} : { details: error.details }),
    },
    requestId,
  };
}
