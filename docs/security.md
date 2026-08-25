# Security model

## Defaults

- Loopback-only listeners (`127.0.0.1`), no wildcard/public bind option.
- Deny-by-default sender and workspace policies.
- Read-only remote posture; every Copilot permission is explicitly mediated.
- One-time approval nonces expire after five minutes by default.
- Output is redacted and bounded before it reaches a channel.
- Audit payloads are structured, redacted, and do not contain message bodies.

## Remote approval scope

Approval summaries include the permission kind and only the minimum useful
scope: command, canonical path label, MCP tool, or network host. The nonce is
bound to:

- channel ID
- local tenant ID
- negotiated bot/account ID
- conversation ID
- sender ID
- Copilot session ID
- permission scope hash
- expiration time

Replays, mismatched identities, expired decisions, and second consumption are
rejected and audited.

## Data handling

Secrets matching common token/key formats and local absolute paths are replaced
before outbound delivery. The gateway never sends Copilot reasoning events,
hidden context, raw tool calls, raw errors, or permission payloads to IM.

The local SQLite database stores iLink credentials, update cursors, and
conversation context tokens only as version-1 AES-256-GCM envelopes. Associated
data binds each record to the envelope version, tenant, channel, account, and
state key, so moving ciphertext between records fails authentication. Public
account labels used by status are stored separately. A random 256-bit master key
lives outside SQLite and is never logged or included in release archives.

On POSIX, the key directory and key must be owned by the operator with modes
0700 and 0600. Creation is exclusive, flushed, and atomically renamed. On
Windows, the bundled PowerShell helper builds a protected DACL containing only
the current operator SID, sets that SID as owner, and verifies the resulting
owner, inheritance, rules, file type, and key length before launching Node. The
daemon fails closed without that verification. Existing encrypted databases
never create a replacement key when the expected key is missing or wrong.

This protects database copies and backups from disclosure without the separate
key. It does not protect against compromise of the same signed-in OS account
while the daemon can decrypt records. Full-disk encryption remains recommended
for swap, crash dumps, filesystem metadata, and offline device theft.

Inbound authorization uses only a minimal identity envelope. Rejected bodies and
attachments are never materialized or persisted, and denial audits contain only
hashed identity labels. Rejection counts are aggregated by hashed
route/sender/reason in a hard-capped 256-slot store with immediate seven-day
cleanup, independent of inbox and audit retention. Unique unauthorized message
IDs therefore cannot grow SQLite state. Terminal inbox metadata is retained for
14 days and audit metadata for 30 days by default. Completed message bodies are
scrubbed after 24 hours, failed bodies after 72 hours, and context tokens expire
after seven days. An expired context token remains available while its exact
tenant/channel/account/conversation still has pending, leased, retry-wait, or
reserved work; it is removed only after that work becomes terminal. Cleanup is
transactional, capped at 500 records of each kind per pass, and never removes
or scrubs active messages.

Schema version 4 migrates v2/v3 plaintext channel records in one SQLite
transaction only after the key is durable. Restart repeats an interrupted
migration safely. Startup requires a fully successful truncating WAL checkpoint
after migration or secret rewrites; a reader that pins sensitive WAL frames
causes startup to fail closed and a later restart can retry. Ambiguous v1 state
without account identity remains quarantined and cannot become active; the
operator must log in again. Exporting or copying SQLite yields only
authenticated envelopes, not plaintext.

Offline rotation uses `dist/daemon/maintenance.js rotate-credential-key
<data-directory>` on POSIX. On Windows use `credential-key.ps1 -Rotate
-NodePath <node.exe> -MaintenanceEntryPoint
<dist\daemon\maintenance.js>`. The daemon must be stopped; SQLite ownership
rejects a live owner. POSIX fsyncs the journal's parent before re-encryption and
after every rename or removal. Windows uses `MoveFileEx` with
`MOVEFILE_WRITE_THROUGH`, verifies each result and ACL, and first moves old key
material intact to the exact retirement marker and key ID recorded in the
durable journal. Only after the new canonical key is committed does it mark the
journal as wiping, best-effort overwrite the isolated marker, delete it, and
flush the parent directory. A torn wipe affects only that marker: the canonical
key can start while later recovery retries cleanup. Marker paths, sizes, ACLs,
and pre-wipe key IDs are validated to reject substituted files or reparse
points. A strict journal and database key ID make every interruption resolve to
exactly the old or new key. The Windows launcher validates and completes a
journaled crash state before enforcing the canonical key path, so a crash
between either key rename remains restart-safe.

## Installer shutdown trust

Automatic Windows upgrade shutdown trusts only the process owning the exact
configured IPv4 loopback Listen socket. The guard fails closed unless
`Get-NetTCPConnection` and CIM resolve one owner, that owner is the sole exact
installed daemon command, and its PID, creation marker, executable, and
tokenized entrypoint remain unchanged after identity verification. The guard
opens a credential-free TCP connection before the final owner resolution and
writes the bearer and shutdown body only to that same non-reconnecting socket.
A listener replacement after connection cannot inherit the established stream.

The identity exchange is HMAC-authenticated without a bearer header. Its
one-use, ten-second challenge binds the daemon instance ID, actual Node PID,
listener port, installer-observed creation marker and process paths, client
nonce, and expiry. Shutdown additionally requires the bearer token and consumes
that same challenge before acknowledgement. Expired and consumed records remain
five-minute replay tombstones, and capacity exhaustion fails with a retryable
503 rather than evicting any live record or tombstone. A restarted daemon, PID
reuse, challenge replay, listener-owner race, ambiguous process set, or non-IPv4
loopback listener therefore cannot receive automatic shutdown. Failure requires
manual exit; the guard never kills a process or modifies gateway data.

## Governance limitation and intended trust root

The personal repository does **not** currently have an active Ruleset
`workflows` rule: GitHub's repository API returned HTTP 422 when that rule was
requested at this scope. Current branch protection requires `Required policy`
and CI. Those checks and the governance verifier remain mandatory and must not
be weakened, but a status context produced in the same repository is not strong
identity separation.

Strong separation requires either an organization-level required workflow or a
dedicated external GitHub App/check identity. If one becomes available,
configure it for `main` with no bypass actors and this immutable workflow
identity:

| Field | Required value |
| --- | --- |
| Repository full name | `cloga/copilot-im-gateway` |
| `repository_id` | `1343812506` |
| Workflow path | `.github/workflows/governance-required.yml` |
| Workflow ref | `refs/heads/main` |
| Workflow SHA | `<merge-commit-sha>`: the exact 40-character commit SHA produced when this bootstrap is merged onto `main` |
| `do_not_enforce_on_create` | `false` |

The rule selects the trusted workflow independently of the PR tree.
`github.workflow_sha` must equal the rule's immutable source SHA and is the
workflow's checkout and execution pin. The first step validates that it is a
full SHA together with the exact event, repository name and ID, base, branch,
author, and actor semantics. The workflow then installs only dependencies from
that checked-out commit. It fetches the event base and untrusted head as git
objects, never checks out or executes the PR head, and runs the trusted
`scripts/governance-check.mjs`. The checker reads BASE and HEAD blobs with git
and requires the HEAD copy of every workflow, including this one, to match the
exact protected AST. A PR therefore cannot forge or weaken the workflow that is
currently enforcing it.

The trusted policy also enumerates every governance, packaging, release, and
installer executable together with the executable lint, test, coverage, and
compiler configurations. The checker compares their HEAD blobs byte-for-byte
with the `github.workflow_sha` tree before permitting the change. Package
scripts invoked by CI or release workflows are matched to their complete
expected command set, and their implicit npm `pre*` and `post*` lifecycle hooks
are forbidden. Dependency declarations and the complete transitive npm lock are
also compared with the trusted tree; only the package's own version fields are
excluded so a release version can advance without changing its toolchain.
Updating this executable control plane or dependency graph therefore requires
the same audited administrator action that advances the Ruleset's immutable
workflow SHA; merely changing a protected script, tool configuration, or
dependency resolution in a PR cannot weaken a later release.

The checked-in required-workflow design is retained for that future trust root;
it is not evidence that such a rule is active today.

For merge queues, `merge_group/checks_requested` must target
`refs/heads/main`. The same trusted checker evaluates the semantic diff from
the event base SHA to the synthetic merge-group head SHA. PR runs already
enforce same-repository branch, author, and actor identity; merge-group payloads
do not provide those PR fields.

If an eligible required-workflow trust root is configured, the repository owner replaces
`<merge-commit-sha>` in the Ruleset request with the resulting `main` merge
commit, immediately removes the obsolete `Protected policy` branch-status
requirement, and creates the active `workflows` rule. The old BASE-only label
gate cannot approve removal of its own blocking condition, so this single
administrative merge is necessary and is not a reusable bypass. After
activation there are no governance labels, and the PR head cannot supply the
required workflow. Every later workflow-SHA or rule update is an audited
administrator action. Agents must never create, update, disable, or bypass live
rulesets or add automation that does so. Current branch-protection status
contexts are required controls, but not a separately hosted trust root.

## Explicit non-goals

- Public or hosted gateway operation
- Organization/multi-tenant administration
- Automatic approval of remote side effects
- Routing Microsoft work data through personal messaging accounts
- Reverse-engineered Copilot APIs or authentication
- Generic ACP/`copilot --acp` backends or arbitrary agent commands
- Replacing the official `joinSession()` extension with an external CLI wrapper
- Live iLink or other external-network access in default automated tests
