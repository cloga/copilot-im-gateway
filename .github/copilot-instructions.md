# Copilot instructions

Follow [`AGENTS.md`](../AGENTS.md) and the machine-enforced
[`agent-policy.json`](agent-policy.json). The sole quality gate is
`npm run verify`.

Preserve the ONLINE product architecture: WeChat iLink, the authenticated
loopback daemon with SQLite, the Canvas, and the GitHub Copilot App extension
using the official SDK `joinSession()` API. Never introduce or reserve
`copilot --acp`, a generic ACP backend, an arbitrary agent command, a
reverse-engineered Copilot model/authentication API, or an external CLI wrapper
in place of the extension.

Default tests must remain deterministic and may use fixture transports and
loopback HTTP only. Do not weaken CI, coverage, governance, security tests,
release verification, installer smoke checks, or generated-artifact policy.
