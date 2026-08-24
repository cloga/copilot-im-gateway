# Architecture

## Components

```text
WeChat iLink
  <-> WeixinAdapter
  <-> Gateway daemon (SQLite, routing, policy, approvals, audit)
  <-> authenticated loopback API
  <-> project Copilot extension (joinSession)
  <-> current foreground Copilot session
  <-> admin Canvas (loopback renderer)
```

The daemon owns all durable and long-lived state. The extension is deliberately
ephemeral because Copilot reloads extensions on `/clear` and foreground-session
replacement.

This is the complete product architecture, not an interchangeable backend
slot. The extension must continue to use the official SDK `joinSession()` API
and must not be replaced by an external CLI wrapper. Generic ACP processes,
`copilot --acp`, arbitrary agent commands, and reverse-engineered Copilot
authentication/model APIs are explicitly outside the architecture.

## Routing

An inbound route key is `channelId:conversationId`. It maps to a durable binding
containing the Copilot session ID and an allowed workspace alias. The daemon
leases inbound messages to the extension; the extension submits the turn to the
foreground session only when the session and workspace match the binding.

Turns are serialized per route key. This avoids response interleaving while
allowing unrelated conversations to proceed concurrently.

## Permission flow

The extension installs `onPermissionRequest`; it never uses `approveAll`.

1. Copilot emits a typed permission request.
2. The extension converts it to a redacted scope summary.
3. The daemon persists a pending approval and returns a one-time nonce.
4. The channel sends an approve/deny command containing the nonce.
5. The daemon validates expiry and the sender/channel/conversation/session tuple.
6. The extension consumes the decision exactly once and returns
   `{ kind: "approved" }` or `{ kind: "reject" }` to Copilot.

Read-only operations still require the configured workspace and sender policy.
Managed-policy approvals are never bypassed.

## Trust boundaries

- **IM is untrusted:** messages, sender IDs, media metadata, and commands are
  hostile input.
- **Daemon API is local but authenticated:** loopback is not an identity
  boundary; all non-health requests require a token and constant-time compare.
- **Canvas is local:** it receives a short-lived per-instance token and proxies
  only allowlisted daemon operations.
- **Copilot runtime is authoritative:** model access, tools, sessions, and
  permission decisions go through the official SDK/CLI runtime.
- **Workspace aliases are capabilities:** an alias resolves to one canonical,
  explicitly configured root. IM input never becomes a path.

## Durability

SQLite stores normalized messages, bindings, aliases, approvals, and audit
events. Message IDs are unique per channel to provide idempotency. State changes
and their audit records use the same transaction where practical.

## Extension lifecycle

The project extension is discovered from
`.github/extensions/im-gateway/extension.mjs`. It joins only the current
foreground session, polls the daemon while alive, and stops on session shutdown
or process termination. No credential or conversation state is kept only in the
extension process.

## Governance invariants

Repository policy protects the extension, loopback listeners, security tests,
coverage floor, release scripts, installer verification, and workflow closure.
Coverage includes the Canvas, gateway client, and side-effect-free extension
runtime. Only the thin `joinSession()` bootstrap entrypoint is excluded because
importing it joins the live foreground session.
Default automated tests use deterministic transports and loopback HTTP; live
iLink/network behavior remains a manual smoke test. See
[change-impact.md](change-impact.md) for required regression evidence.
