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

`Required governance / Required policy` and CI are the active branch-protection
gates. The personal-repository API returned HTTP 422 for GitHub's Ruleset
`workflows` rule, so that stronger trust root is not active. The checked-in
required workflow first validates the event and repository
identity, then checks out exactly `github.workflow_sha`, installs that trusted
commit's dependencies, and treats the pull-request or merge-group trees only as
git data. Same-repository `cloga/*` branches require both the `cloga` PR author
and event actor; Dependabot branches require `dependabot[bot]` for both. Forks
cannot satisfy branch policy. Protected-path changes remain reported and must
pass the exact workflow allowlist, pinned-Action, quality-closure, coverage,
test-retention, content, and architecture checks. Governance, packaging, release, and installer executables and their lint, test,
coverage, and compiler configurations must remain byte-identical to the
`github.workflow_sha` tree. Protected npm lifecycle hooks are forbidden.
Dependency declarations and the transitive npm lock are also pinned, except for
the application version fields. Changing that executable control plane or
dependency graph requires an audited administrator update of the immutable
Ruleset pin.

An organization-level required workflow or dedicated external GitHub App/check
identity is required for strong separation. If that becomes available, it must require
`.github/workflows/governance-required.yml` from
`cloga/copilot-im-gateway` (repository ID `1343812506`) at the exact immutable
`<merge-commit-sha>` produced when this bootstrap is merged on `main`.
`github.workflow_sha` is the checkout and execution trust pin. Every future SHA
or rule update is an audited administrator action. Agents must not push, merge,
release, or alter live rulesets and must not weaken current status checks or
governance code. See
`docs/security.md`.

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
