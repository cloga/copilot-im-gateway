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

## Install a release

Prerequisites: Windows PowerShell, Node.js 22.12+ (excluding 23.x) or 24+, npm,
and GitHub Copilot CLI/App 1.0.80+.

1. Download `copilot-im-gateway-v<VERSION>.tgz` and its `.sha256` file from
   [GitHub Releases](https://github.com/cloga/copilot-im-gateway/releases).
2. Verify and extract the archive:

   ```powershell
   $archive = "copilot-im-gateway-v0.1.0.tgz"
   $expected = (Get-Content "$archive.sha256").Split()[0]
   $actual = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
   if ($actual -ne $expected) { throw "Release checksum mismatch" }
   tar -xzf $archive
   Set-Location package
   ```

3. Install production dependencies and the user-scoped Copilot extension:

   ```powershell
   .\install.ps1
   ```

4. Reload extensions in GitHub Copilot App, then start the daemon:

   ```powershell
   & "$HOME\.copilot\im-gateway\start.ps1"
   ```

The release contains compiled JavaScript, so consumers do not need TypeScript,
development dependencies, or a local build. The installer runs
`npm ci --omit=dev --ignore-scripts`, installs under
`$HOME\.copilot\im-gateway`, and copies only the versioned extension files to
`$HOME\.copilot\extensions\im-gateway`. It does not read or write credentials.

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
| `npm run release:package` | Build the release archive and SHA-256 checksum |
| `npm run release:validate` | Validate release contents and checksum |
| `npm run release:verify` | Verify contents and deterministic packaging |
| `npm run check` | Run lint, typecheck, tests, build, and release verification |

## Maintainer release

1. Update `version` in `package.json` and `package-lock.json`.
2. Open and merge a pull request after `npm run check` passes.
3. Tag the merged commit with the matching semantic version, for example
   `v0.2.0`, and push the tag.
4. The `Release` workflow checks the tag against `package.json`, runs the full
   check, builds once in CI, publishes the archive and checksum, and generates
   GitHub Release notes.

Do not create a tag for an unmerged commit. GitHub Releases are the distribution
channel; no npm publishing credentials are required. Live WeChat QR login and
message delivery cannot be automated safely and remain a
[manual smoke test](docs/manual-smoke-test.md).

## Prior art

The normalized adapter, stable routing, persisted session mapping, serial turn
queue, streaming/final routing, and hot channel lifecycle are informed by the
MIT-licensed
[lijian-ui/dsh-im-gateway](https://github.com/lijian-ui/dsh-im-gateway).
This repository is a clean implementation for the official GitHub Copilot SDK
runtime; no source code from that project is copied.
