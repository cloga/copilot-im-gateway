# Copilot IM Gateway

Secure, local-first instant-messaging gateway for GitHub Copilot. The first
vertical slice connects WeChat iLink to the current foreground Copilot session
through the official GitHub Copilot SDK extension runtime.

> [!WARNING]
> This project is for personal/local hobby use. Do not route Microsoft work
> repositories, credentials, messages, or other company data through personal
> WeChat.

## What is included

- A durable daemon bound to `127.0.0.1` with bearer authentication.
- Generic channel contracts, stable `channelId:conversationId` routing, durable
  bindings, serial turn processing, deduplication, rate limiting, redaction,
  bounded output, audit records, and expiring one-time approvals.
- A WeChat iLink adapter with a protocol boundary that can use the real service
  or deterministic fixtures.
- A project-scoped Copilot extension that joins the foreground session with
  `joinSession()`, forwards approved inbound turns with `session.send()`, and
  publishes safe final output through the daemon.
- An experimental in-app Canvas for login, health, bindings, workspace aliases,
  pending approvals, and audit visibility.

## Quick start

Prerequisites: Node.js 22.12+ and GitHub Copilot CLI/App 1.0.80+.

```powershell
npm ci
npm run build
npm test
npm run daemon
```

The first daemon start creates a local bearer token in the data directory with
owner-only permissions where supported. Inspect the startup message for the
token file path; the token itself is never printed. Set
`COPILOT_IM_GATEWAY_TOKEN_FILE` for the extension if using a non-default data
directory.

See [docs/development.md](docs/development.md) for setup and verification,
[docs/architecture.md](docs/architecture.md) for design invariants, and
[docs/manual-smoke-test.md](docs/manual-smoke-test.md) for the QR login flow.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run bootstrap` | Deterministic dependency installation |
| `npm run daemon` | Start the local gateway daemon |
| `npm run dev` | Start the daemon with TypeScript source |
| `npm run lint` | Lint source, tests, scripts, and extension code |
| `npm run typecheck` | Type-check without emitting |
| `npm test` | Run deterministic unit/integration tests |
| `npm run build` | Compile production JavaScript |
| `npm run check` | Run lint, typecheck, tests, and build |

## Prior art

The normalized adapter, stable routing, persisted session mapping, serial turn
queue, streaming/final routing, and hot channel lifecycle are informed by the
MIT-licensed
[lijian-ui/dsh-im-gateway](https://github.com/lijian-ui/dsh-im-gateway).
This repository is a clean implementation for the official GitHub Copilot SDK
runtime; no source code from that project is copied.
