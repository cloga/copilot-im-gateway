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
- Generic channel contracts, collision-safe account-aware route identities,
  durable bindings, per-route FIFO processing, deduplication, rate limiting, redaction,
  bounded output, audit records, and expiring one-time approvals.
- A WeChat iLink adapter with a protocol boundary that can use the real service
  or deterministic fixtures.
- A project-scoped Copilot extension that joins the foreground session with
  `joinSession()`, forwards approved inbound turns with `session.sendAndWait()`, and
  publishes safe final output through the daemon.
- An experimental in-app Canvas for login, health, bindings, workspace aliases,
  pending approvals, and audit visibility.

## Install a release

GitHub Copilot CLI/App 1.0.80+ is required. The recommended Windows installer
includes the application runtime and does not require Node.js, npm, or
TypeScript.

### Windows

1. Download `Copilot-IM-Gateway-Setup-v0.1.2-x64.exe` and
   `Copilot-IM-Gateway-Setup-v0.1.2-x64.exe.sha256` from
   [GitHub Releases](https://github.com/cloga/copilot-im-gateway/releases).
2. Verify the installer:

   ```powershell
   $installer = "Copilot-IM-Gateway-Setup-v0.1.2-x64.exe"
   $expected = (Get-Content "$installer.sha256").Split()[0]
   $actual = (Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant()
   if ($actual -ne $expected) { throw "Release checksum mismatch" }
   ```

3. Run the installer. It installs per-user under
   `%LOCALAPPDATA%\Programs\Copilot IM Gateway`, registers the extension under
   `%USERPROFILE%\.copilot\extensions\im-gateway`, and creates Start Menu
   shortcuts. During an upgrade it uses the local bearer token to request
   authenticated v2 daemon shutdown and waits for the process and loopback port
   to be released. If an older daemon or another listener cannot accept that
   request, Setup leaves the existing installation and data untouched. Exit the
   old Copilot IM Gateway and retry. Reload extensions in GitHub Copilot App
   after installation.
4. Open **Start Copilot IM Gateway** from the Start Menu. The installer does not
   configure persistent auto-start.
5. Use **Gateway status** to open the unauthenticated local health endpoint.
   Uninstall from Windows Installed Apps or the Start Menu shortcut.

> [!WARNING]
> The initial Windows Setup EXE is not code-signed. Windows SmartScreen may show
> an "unrecognized app" warning. Verify the published SHA-256 checksum before
> choosing **More info** and **Run anyway**. The release does not claim a trusted
> publisher signature.

The existing Windows ZIP remains available for advanced users. It does not
bundle Node.js and still requires Windows PowerShell, a supported Node.js
version, and npm before running `install.ps1`.

### Cross-platform archive

Cross-platform users can instead download
`copilot-im-gateway-v0.1.2.tgz` and its `.sha256` file, verify it with their
platform's SHA-256 tool, and extract it with:

```sh
tar -xzf copilot-im-gateway-v0.1.1.tgz
cd package
```

The release contains compiled JavaScript, so consumers do not need TypeScript,
development dependencies, or a local build. The installer runs
`npm ci --omit=dev --ignore-scripts`, installs under
`$HOME\.copilot\im-gateway`, and copies only the versioned extension files to
`$HOME\.copilot\extensions\im-gateway`. It stops an installed daemon before
replacement by reading its local bearer-token file without displaying or
copying the credential. An upgrade aborts before replacement if authenticated
v2 shutdown is unavailable; exit the old Copilot IM Gateway and retry.

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
| `npm run test:coverage` | Run deterministic tests with all production source measured |
| `npm run coverage:check` | Enforce the protected coverage floor |
| `npm run audit:check` | Audit dependencies explicitly |
| `npm run policy:check` | Enforce diff-aware local repository policy |
| `npm run build` | Compile production JavaScript |
| `npm run release:package` | Build the `.tgz` and Windows `.zip` archives and checksums |
| `npm run release:installer` | Build the self-contained Windows x64 Setup EXE and checksum |
| `npm run release:installer:smoke` | Silently install, probe, and uninstall the Windows Setup EXE |
| `npm run release:validate` | Validate release contents and checksums |
| `npm run release:verify` | Verify contents and deterministic packaging |
| `npm run verify` | Run the canonical lint, type, coverage, build, audit, policy, and release gate |
| `npm run check` | Compatibility alias for `npm run verify` |

## Maintainer release

1. Update `version` in `package.json` and `package-lock.json`.
2. Open and merge a pull request after `npm run verify` passes.
3. Tag the merged commit with the matching semantic version, for example
   `v0.2.0`, and push the tag.
4. The `Release` workflow checks the tag against `package.json`, runs the full
   canonical verify gate, builds once in CI, publishes both archives, the Windows Setup EXE,
   and all checksums, and generates GitHub Release notes.

Do not create a tag for an unmerged commit. GitHub Releases are the distribution
channel; no npm publishing credentials are required. Live WeChat QR login and
message delivery cannot be automated safely and remain a
[manual smoke test](docs/manual-smoke-test.md).

After governance bootstrap, maintainers must protect `v*` tags with a repository
ruleset or require a protected release environment. The Release workflow also
fetches `origin/main` and rejects any tag commit that is not on its ancestry
before running npm or packaging scripts.

## Prior art

The normalized adapter, stable routing, persisted session mapping, serial turn
queue, streaming/final routing, and hot channel lifecycle are informed by the
MIT-licensed
[lijian-ui/dsh-im-gateway](https://github.com/lijian-ui/dsh-im-gateway).
This repository is a clean implementation for the official GitHub Copilot SDK
runtime; no source code from that project is copied.
