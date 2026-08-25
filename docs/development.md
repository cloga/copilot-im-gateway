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
if ($IsWindows) {
  . .\scripts\release\credential-key.ps1
}
npm run dev
```

The daemon reports its loopback URL, never token values, credential values, or
credential-key paths. On Windows the ACL helper must run in the same PowerShell
process so the daemon receives its verified operator-only ACL attestation.
The installed daemon and extension are a compatibility unit: `/v2/status`
advertises the required API capabilities, and the extension refuses unsafe work
with `DAEMON_UPGRADE_REQUIRED` when they are missing. Release validation includes
the complete transitive compiled daemon ESM closure and every extension runtime
file in the same archive.

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

The personal repository API currently returns HTTP 422 for a repository
Ruleset `workflows` rule. Branch protection therefore requires `Required
policy` and CI today. Strong workflow identity separation requires an
organization-level required workflow or a dedicated external GitHub App/check
identity; see [security.md](security.md). Do not weaken the checked-in
governance verifier while that limitation remains.

The rule requires `.github/workflows/governance-required.yml` from
`cloga/copilot-im-gateway` (repository ID `1343812506`). The workflow has only
`contents: read`; its first step validates the event and
`github.workflow_sha`, and its pinned checkout uses that SHA. Dependencies and
the checker therefore come only from the immutable Ruleset source commit. The
event base, PR head, and merge-group head are fetched only as git objects and
are never checked out or executed.

Governance, packaging, release, and installer executables and their lint, test,
coverage, and compiler configurations are immutable relative to
`github.workflow_sha`. Every package command invoked by protected workflows is
checked exactly, and npm `pre*`/`post*` hooks are denied for those commands. A
dependency declaration or transitive lockfile change is pinned as part of the
same trusted toolchain, except for the application version fields. A legitimate
executable control-plane or dependency update requires an audited administrator
bootstrap and Ruleset repin; ordinary runtime and documentation changes continue
through the semantic checker without that operation.

The trusted checker parses HEAD workflow YAML as untrusted data with the pinned
parser and rejects aliases, anchors, custom tags, duplicate keys,
explicit/quoted mapping keys, flow collections, folded values, local Actions,
and non-SHA Action references. CI, Required governance, and Release workflows
must exactly match the protected AST allowlist. Pull-request events enforce
same-repository `cloga/*` or Dependabot branch, author, and actor identities.
`merge_group/checks_requested` evaluates the synthetic queue head against
`refs/heads/main` with the same semantic checks.

Protected paths remain visible without an approval label. Every future Ruleset
or source-SHA update is an audited administrator action. Current
branch-protection status contexts are required controls, but are not a
separately hosted trust root.
Agents must not modify live rulesets or add API automation that does so.
