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

The local SQLite database and bearer token should be protected by OS user
permissions and disk encryption. The project does not provide multi-user host
isolation in this initial personal/local scope.

## Explicit non-goals

- Public or hosted gateway operation
- Organization/multi-tenant administration
- Automatic approval of remote side effects
- Routing Microsoft work data through personal messaging accounts
- Reverse-engineered Copilot APIs or authentication
- Generic ACP/`copilot --acp` backends or arbitrary agent commands
- Replacing the official `joinSession()` extension with an external CLI wrapper
- Live iLink or other external-network access in default automated tests
