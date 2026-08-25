# Change impact guide

Every pull request must identify affected boundaries and include the matching
evidence.

| Area | Required impact analysis and verification |
| --- | --- |
| `src/core/**` | Security invariants, redaction/approval behavior, deterministic unit regression |
| `src/daemon/**` | Authentication, loopback-only binding, SQLite durability, localhost integration regression |
| `src/channels/**` | Protocol compatibility, fixture transport regression, no live iLink in default tests |
| `.github/extensions/im-gateway/**` | Official SDK `joinSession()` lifecycle, permission mediation, Canvas/daemon mock and manual reload |
| Release or installer | Deterministic archives, checksums, consumer validation, Windows installer build/smoke |
| CI or governance | Permission review, immutable Action SHAs, exact workflow semantics, `github.workflow_sha` execution pin, required-workflow Ruleset trust tuple and merge-queue behavior |
| Dependencies | Lockfile, audit result, runtime/development scope, Dependabot impact |

Do not propose generic agent commands, ACP backends, public listeners,
reverse-engineered Copilot APIs, live-service default tests, or weaker quality
gates as alternatives. Runtime/security changes must modify or add a focused
test; deleting tests is denied. Generated build, coverage, daemon state, token,
archive, installer, and checksum files stay untracked.
