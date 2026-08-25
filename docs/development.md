# Development

## Bootstrap

```powershell
npm ci --ignore-scripts --no-audit --no-fund
npm run verify
```

The lockfile is authoritative. Do not add setup steps that require global npm
packages, copied secrets, or interactive configuration.

## Local daemon

```powershell
$env:COPILOT_IM_GATEWAY_DATA_DIR = "$PWD\.copilot-im-gateway"
npm run dev
```

The daemon reports its loopback URL and token file path, never the token value.
The installed daemon and extension are a compatibility unit: `/v2/status`
advertises the required API capabilities, and the extension refuses unsafe work
with `DAEMON_UPGRADE_REQUIRED` when they are missing. Release validation includes
both the compiled daemon entrypoint and every extension runtime file in the same
archive.

## Extension

The versioned project extension is loaded automatically during repository
development. Install the same files as a user-scoped extension with:

```powershell
npm run extension:install
```

After changes, reinstall when using the user-scoped copy, reload extensions,
and inspect `im-gateway`. Standard output is reserved for JSON-RPC; extension
diagnostics must use `session.log()` or standard error.

## Verification matrix

| Change | Minimum verification |
| --- | --- |
| Core policy/security | Focused unit tests and `npm run typecheck` |
| Daemon API/storage | Loopback integration tests |
| Channel protocol | Fixture transport tests |
| Extension/Canvas | Syntax/typecheck, extension reload/inspect, daemon mock |
| Any production change | `npm run verify` and `git diff --check` |

Live QR scanning is intentionally outside automated CI. Follow
[manual-smoke-test.md](manual-smoke-test.md).

`npm run check` remains a compatibility alias for `npm run verify`. For a local
worktree whose app-generated branch name cannot use the required `cloga/`
prefix, set `AGENT_POLICY_HEAD_REF=cloga/<remote-name>` while running verify.
CI always validates the actual PR head ref.

The first governance PR is a trust-on-first-use bootstrap: remote `main` cannot
enforce a governance workflow it does not yet contain. Independently review
that PR, then configure a ruleset requiring the Verify matrix and
`Governance / Protected policy`. Protected changes need a fresh non-author
maintainer `manual-governance` label after every synchronize event.

The governance checker installs only the protected BASE lockfile, parses head
workflow YAML as untrusted data with the pinned parser, and rejects aliases,
anchors, custom tags, duplicate keys, explicit/quoted mapping keys, flow
collections, folded values, local Actions, and non-SHA Action references. CI,
Governance, and Release workflows must exactly match the protected AST
allowlist.

For label/reopen events, the workflow accepts the current head only when an
earlier protected opened/synchronize run created a successful
`governance-head-<SHA>` artifact after verifying the expected `cloga` or
`dependabot[bot]` actor. Artifact upload uses the pinned Actions runtime and
works with Dependabot's read-only `GITHUB_TOKEN`; later events only need
`actions: read`. The reader verifies the artifact's source run path, event,
actor, and repository, then verifies the sole file binds the SHA, actor, and PR
number. A failed synchronize from another writer cannot be made green by
relabeling the pull request.
