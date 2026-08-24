# Agent guide

## Mission

Maintain a secure, local-first IM gateway that uses only official GitHub
Copilot App extension SDK/CLI APIs. The sole quality gate is `npm run verify`;
machine-enforced policy lives in `.github/agent-policy.json`.

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
11. Preserve the ONLINE product shape: official SDK `joinSession()` extension,
    Canvas, authenticated loopback daemon, SQLite, and WeChat iLink.
12. Never add, recommend, or reserve `copilot --acp`, a generic ACP backend, or
    arbitrary agent commands as a product mode. The extension must not become an
    external CLI wrapper.
13. Never use reverse-engineered Copilot authentication/model endpoints, token
    extraction, browser-token scraping, or wildcard/public listeners.
14. Default tests use injected fixtures and loopback only, never live iLink,
    real messages, credentials, or external network.

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
4. Run `npm run verify`.
5. For extension changes, reload and inspect the extension in Copilot App.
6. Review `git diff --check` and ensure no generated data or secrets are staged.

## Governance

CI invokes `npm run verify` on Windows and Linux across the supported Node
lines. Coverage includes all production files and must meet or exceed
`.github/coverage-baseline.json`; the baseline is a floor, not an exact target.
Do not weaken CI, coverage, security tests, release/installer verification, or
the canonical verification closure.

`Governance / Protected policy` runs from `pull_request_target`, checks out and
executes only protected BASE code and BASE-pinned dependencies, and treats the
PR head only as git data. Same-repository `cloga/*` branches are bound to the `cloga` PR author and
authoring-event actor; Dependabot branches require the real `dependabot[bot]`
PR author and opened/synchronize actor. Label events are instead bound to the
independently authorized maintainer actor. Forks cannot satisfy branch policy.
Changes to workflows, CODEOWNERS, policy/checkers, quality closure, coverage,
security tests, release scripts, or installer verification require a fresh
`manual-governance` label event from a non-author maintainer. Synchronizing the
PR invalidates the successful approval run, so the label must be removed and
freshly reapplied. Coverage baseline decreases and test deletion remain denied.

This first governance PR is trust-on-first-use because remote `main` cannot run
a workflow it does not yet contain. It requires independent review before
merge. After merge, configure the repository ruleset to require both Verify and
Governance checks; agents must not push, merge, release, or change that ruleset.
Also configure a protected `v*` tag ruleset or release environment. The Release
workflow independently rejects tag commits that are not reachable from
`origin/main`.

## Coding conventions

- TypeScript strict mode; no `any`, broad catches, or silent fallbacks.
- Validate all external JSON with Zod.
- Pass clocks, random sources, transports, and storage into security/protocol
  code so tests remain deterministic.
- Use structured audit events, not free-form security logs.
- Keep comments rare and focused on invariants or non-obvious protocol behavior.
