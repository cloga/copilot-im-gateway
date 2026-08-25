# Security model

## Defaults

- Loopback-only listeners (`127.0.0.1`), no wildcard/public bind option.
- Deny-by-default sender and workspace policies.
- Read-only remote posture; every Copilot permission is explicitly mediated.
- One-time approval nonces expire after five minutes by default.
- Output is redacted and bounded before it reaches a channel.
- Audit payloads are structured, redacted, and do not contain message bodies.

## Remote approval scope

Approval summaries include the permission kind and only the minimum useful
scope: command, canonical path label, MCP tool, or network host. The nonce is
bound to:

- channel ID
- local tenant ID
- negotiated bot/account ID
- conversation ID
- sender ID
- Copilot session ID
- permission scope hash
- expiration time

Replays, mismatched identities, expired decisions, and second consumption are
rejected and audited.

## Data handling

Secrets matching common token/key formats and local absolute paths are replaced
before outbound delivery. The gateway never sends Copilot reasoning events,
hidden context, raw tool calls, raw errors, or permission payloads to IM.

The local SQLite database currently stores iLink credentials in plaintext.
Protect the database and bearer token with OS user permissions and disk
encryption. Application-level credential encryption is the next defense layer;
the project does not provide multi-user host isolation in this personal/local
scope.

Inbound authorization uses only a minimal identity envelope. Rejected bodies and
attachments are never materialized or persisted, and denial audits contain only
labeled identity hashes. Rejection counts are aggregated by hashed
route/sender/reason in a hard-capped 256-slot store with immediate seven-day
cleanup, independent of inbox and audit retention. Unique unauthorized message
IDs therefore cannot grow SQLite state. Terminal inbox metadata is retained for
14 days and audit metadata for 30 days by default.

## Installer shutdown trust

Automatic Windows upgrade shutdown trusts only the process owning the exact
configured IPv4 loopback Listen socket. The guard fails closed unless
`Get-NetTCPConnection` and CIM resolve one owner, that owner is the sole exact
installed daemon command, and its PID, creation marker, executable, and
tokenized entrypoint remain unchanged after identity verification. The guard
opens a credential-free TCP connection before the final owner resolution and
writes the bearer and shutdown body only to that same non-reconnecting socket.
A listener replacement after connection cannot inherit the established stream.

The identity exchange is HMAC-authenticated without a bearer header. Its
one-use, ten-second challenge binds the daemon instance ID, actual Node PID,
listener port, installer-observed creation marker and process paths, client
nonce, and expiry. Shutdown additionally requires the bearer token and consumes
that same challenge before acknowledgement. Expired and consumed records remain
five-minute replay tombstones, and capacity exhaustion fails with a retryable
503 rather than evicting any live record or tombstone. A restarted daemon, PID
reuse, challenge replay, listener-owner race, ambiguous process set, or non-IPv4
loopback listener therefore cannot receive automatic shutdown. Failure requires
manual exit; the guard never kills a process or modifies gateway data.

## Explicit non-goals

- Public or hosted gateway operation
- Organization/multi-tenant administration
- Automatic approval of remote side effects
- Routing Microsoft work data through personal messaging accounts
- Reverse-engineered Copilot APIs or authentication
- Generic ACP/`copilot --acp` backends or arbitrary agent commands
- Replacing the official `joinSession()` extension with an external CLI wrapper
- Live iLink or other external-network access in default automated tests
