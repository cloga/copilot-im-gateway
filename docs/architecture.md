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

An inbound route identity explicitly contains the local tenant, adapter ID,
negotiated bot/account ID, conversation/thread ID, and sender owner. Components
are length-prefixed and SHA-256 hashed into the durable route key, so delimiter
ambiguity and cross-account state sharing are impossible. It maps to a binding
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
5. The daemon validates expiry, tenant/account/route/sender/session identity, and
   the stable operation/scope digest.
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

SQLite stores normalized messages, bindings, aliases, approvals, rate windows,
admission dispositions, ownership and work leases, and audit events. Message IDs
are idempotent per full route. `BEGIN IMMEDIATE` couples state transitions with
their audit records. Durable sequence numbers prevent retrying work from being
overtaken after restart. Terminal inbox metadata and audit data default to
14-day and 30-day retention respectively.

Startup first binds the configured port on `127.0.0.1`. The same HTTP server
holds that listener while SQLite is opened and migrated, returns `503` until
channels are ready, and then receives the real request handler. A bind failure
therefore leaves even a legacy database untouched.

Admission reservations carry the owning daemon generation. A replacement daemon
rechecks sender, personal binding, durable rate, and capacity policy before it
reclaims the original sequence. A duplicate still being materialized by the
live owner is retryable, while abandoned reservation barriers expire explicitly
so later FIFO work cannot remain blocked forever. Rejections use a separate
bounded aggregate ring (256 route/sender/reason buckets retained for seven days
by default); rejected message IDs and bodies are not stored.

Transient extension failures use capped durable retries. The bridge is
necessarily at-least-once across the boundary where `sendAndWait()` may succeed
but the completion acknowledgement is lost; prompts and tools should therefore
remain idempotent where possible.

## Extension lifecycle

The project extension is discovered from
`.github/extensions/im-gateway/extension.mjs`. It joins only the current
foreground session, polls the daemon while alive, and stops on session shutdown
or process termination. No credential or conversation state is kept only in the
extension process.

## API compatibility

The extension performs an authenticated `GET /v2/status` handshake before any
lease, completion, outbound, binding, or approval operation. The response pins
API version 2 and the account-routing, sender-binding, operation-approval, and
reservation-ownership capabilities. All current extension and Canvas operations
use `/v2`.

`/v1/status`, audit, login, and workspace-alias operations remain available for
safe diagnostics and setup. Legacy operations whose payload lacks the negotiated
account or sender fail with HTTP 426 and `UPGRADE_REQUIRED`; they are never
silently interpreted as v2. A new extension maps a missing or incomplete v2
handshake to `DAEMON_UPGRADE_REQUIRED` before sending an unsafe request.

Release archives and the Windows installer carry the compiled daemon, its
validated recursive ESM closure manifest, and the complete extension directory
in one package. Installer upgrades send an authenticated, empty-body
`POST /v2/admin/shutdown`; the daemon acknowledges before asynchronously closing
the listener, settling every channel stop, and releasing SQLite ownership.
Upgrades wait for the process and loopback port to exit. There is no process-kill
fallback: a legacy daemon or unknown listener that cannot accept authenticated
v2 shutdown aborts the upgrade before installed files or data are changed. The
user must exit the old Copilot IM Gateway and retry. Startup binding remains the
final fail-closed migration guard. Upgrade those artifacts together rather than
copying an extension or daemon independently.

## Governance invariants

Repository policy protects the extension, loopback listeners, security tests,
coverage floor, release scripts, installer verification, and workflow closure.
Coverage includes the Canvas, gateway client, and side-effect-free extension
runtime. Only the thin `joinSession()` bootstrap entrypoint is excluded because
importing it joins the live foreground session.
Default automated tests use deterministic transports and loopback HTTP; live
iLink/network behavior remains a manual smoke test. See
[change-impact.md](change-impact.md) for required regression evidence.
