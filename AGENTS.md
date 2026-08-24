# Agent Guide

## Mission

Maintain a secure, local-first IM gateway that uses only official GitHub
Copilot SDK/CLI APIs. Never add reverse-engineered model endpoints, Copilot
token extraction, browser-token scraping, or public-by-default listeners.

## Repository map

- `src/core/`: channel-neutral contracts and deterministic security primitives.
- `src/daemon/`: durable state, routing, authenticated localhost API, lifecycle.
- `src/channels/`: channel adapters; protocol details stay below this boundary.
- `.github/extensions/im-gateway/`: foreground-session bridge and admin Canvas.
- `tests/`: unit and localhost integration tests.
- `docs/`: architecture, security, development, and manual smoke tests.

## Non-negotiable invariants

1. Bind daemon and Canvas servers to loopback only.
2. Authenticate every daemon endpoint except `/healthz`.
3. Never accept an arbitrary filesystem path from an IM message. Resolve only
   configured workspace aliases and reject paths outside the explicit allowlist.
4. Never use `approveAll` for remote turns. Every mutating/path/network
   permission requires a one-time, expiring decision bound to sender, channel,
   conversation, and Copilot session.
5. Do not send reasoning, hidden context, tool arguments/results, stack traces,
   secrets, or local absolute paths to IM.
6. Serialize turns per `channelId:conversationId`; different conversations may
   run concurrently.
7. Persist bindings, inbox state, approval state, and audit records before
   acknowledging state-changing API requests.
8. Keep channel code behind `ImChannelAdapter` and `ChannelProtocolClient`.
9. Do not route Microsoft work repositories/data through personal WeChat.
10. Never commit `.env`, tokens, QR credentials, cookies, or daemon data.

## Error contracts

HTTP errors are JSON:

```json
{
  "error": {
    "code": "GATEWAY_STABLE_CODE",
    "message": "Safe user-facing message",
    "retryable": false,
    "details": {}
  },
  "requestId": "uuid"
}
```

Add stable error codes rather than parsing messages. Error details must be safe
for logs and remote display.

## Change workflow

1. Read relevant contracts and tests before editing.
2. Keep changes within package boundaries; do not import daemon internals from
   channel adapters or the extension.
3. Add or update tests for every behavior/security change.
4. Run `npm run check`.
5. For extension changes, reload and inspect the extension in Copilot App.
6. Review `git diff --check` and ensure no generated data or secrets are staged.

## Coding conventions

- TypeScript strict mode; no `any`, broad catches, or silent fallbacks.
- Validate all external JSON with Zod.
- Pass clocks, random sources, transports, and storage into security/protocol
  code so tests remain deterministic.
- Use structured audit events, not free-form security logs.
- Keep comments rare and focused on invariants or non-obvious protocol behavior.
