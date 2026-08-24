# Development

## Bootstrap

```powershell
npm ci
npm run check
```

The lockfile is authoritative. Do not add setup steps that require global npm
packages, copied secrets, or interactive configuration.

## Local daemon

```powershell
$env:COPILOT_IM_GATEWAY_DATA_DIR = "$PWD\.copilot-im-gateway"
npm run dev
```

The daemon reports its loopback URL and token file path, never the token value.

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
| Any production change | `npm run check` and `git diff --check` |

Live QR scanning is intentionally outside automated CI. Follow
[manual-smoke-test.md](manual-smoke-test.md).
