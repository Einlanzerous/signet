# CLAUDE.md

How this repo works, and the invariants in force. `REVIEW.md` is higher
priority for a review; this file describes the system a review is looking at.
Every invariant below is here because signet broke it at least once; `git log`
and the SGNT tickets hold the history.

## What signet is

A single-host credential vault and sync daemon. Secrets live encrypted in
SQLite; signet fans them out to GitHub Actions secrets, renders them into env
files on disk, and injects them into child processes. It ships as a static Go
binary run under systemd on `imperial-construct` — **no container, no image** —
and Switchyard's delivery reconciler polls its `/healthz` for build identity.

Pure Go, no cgo (`modernc.org/sqlite`). The whole test suite runs in-process.
`cmd/signet/main.go` holds every CLI verb and is large (SGNT-37 tracks the
split); that is why the reviewer's effort tier is pinned at high.

## The invariants

### 1. Fix at the layer that owns the invariant, not at the call site

When a change adds a guard, a normalization or a required step, ask which layer
owns that invariant and `grep` for every other caller. "The caller must
remember" is not a design. Example: a mint guard added to `generate` while
`set --generate` did the same write unguarded.

### 2. Reads of a secret's value go through `internal/resolve`

`resolve.Current` is the single read path. Never call `CurrentVersion` +
`vault.Decrypt` directly (the one exception, `clearDerivation`, says so at the
call site). `resolve.ErrNoVersion` is a sentinel callers divide on: `render` and
`status` skip such a secret, `reveal` and push must fail.

### 3. A mutation and its ledger entry are one transaction

Use `store.Mutate` / `store.MutateValue`; never call `AppendAudit` separately
after a mutation. Reads that decide a write belong on `Mutation`
(`GetSecretForUpdate`, `CurrentVersionForUpdate`), or the gate is advisory.
Ledger entries carry a typed `EventKind` and an `ActorRole` supplied by the call
site, never parsed from the free-text `Actor`. `RoleDaemon` and `RoleHealer`
are not declarable by an API caller.

### 4. Plaintext leaves only in audited ways, keyed by `SecretID`

Egress channels (`reveal`, `exec`, rendered targets, the sealed push, signet's
own read of the GitHub PAT) must each leave an entry carrying `SecretID`, so
`signet audit --secret <ref>` answers "where has this credential been". An entry
naming only a `TargetID` leaves that query empty. `internal/disclose` holds the
authoritative list. Egress channels share `KindSecretReveal` deliberately.
A disclosure of a derived secret is a disclosure of its inputs
(`auditDerivedInputs`). A decrypted value never reaches an error message, a log
line, a ledger `Details` field or an HTTP response.

### 5. Hashes of secret material are keyed

`vault.ValueDigest` is an HMAC, never a bare `sha256`: a low-entropy credential
is otherwise brute-forceable out of the database.

### 6. Silence where a failure should be loud

A path must not return success because nothing explicitly failed. Ask of any new
path what it prints when it goes wrong and whether the exit code says so.
Example: a push reached GitHub, wrote no ledger entries and exited 0, because
`PushResult.AuditErr` existed and no CLI caller read it (SGNT-44). Other shapes:
a daemon that stopped without logging (SGNT-19), a preflight that probed the
read and let the write fail (SGNT-29). `render --check` is non-zero so deploys
can gate on it.

### 7. State is reported, not assumed — in either direction

`GHState` defaults to `in sync`; reaching it with neither a version nor a digest
is the most confident answer about something nobody checked. The opposite also
shipped: `render` reported every target "now stale" unconditionally (SGNT-31).
`status`, `render --check` and `render`'s trailing note all go through
`renderState` so they cannot disagree.

### 8. A derived secret has no value of its own

It is composed at read time. No write path may let a derived secret be `set`,
rotated or imported over. Every version write declares its `store.Provenance`
(required, not defaulted): passing `Minted` for an external value makes an
externally-issued credential rotatable.

### 9. Build identity is never guessed

`internal/version` reports bare semver with **no `v` prefix**, or `"dev"`, plus
the full 40-char commit or JSON `null`. Read through `version.Get()`, never the
package vars: a linker flag stamped empty links `""` over the default, so the
fallback lives in `Get()`. The injectors are `.github/workflows/release.yml` and
the `Makefile`; they must agree, and the `Makefile` needs `sed 's/^v//'`.
Example: a `|| echo dev` outside a subshell never fired and VERSION was empty.

### 10. Doc comments are load-bearing

A comment asserting a property the code lacks is a defect, because it stops the
next reader checking. Treat "every X goes through Y" and "this cannot happen" as
claims to verify.

### 11. Agent-reachable surface is a decision, not a default

Some verbs are allowlisted for agents as `Bash(signet <verb>:*)` (`generate`,
`rotate`, `derive`, `sync`, `target`, read-only ones); `reveal` and `exec` are
deliberately not. A new verb, or a flag widening what a verb can do without a
human, needs an allowlist decision before it ships and nothing prompts for one
(`derive` sat outside the rules for a week). Name it in the PR. Destructive
paths require an explicit flag (`--replace`, `--prune`).

## Working in this repo

**Migrations are append-only** (`internal/store/store.go`, `migrations`); never
edit a shipped one. Commits are conventional (PRINCIPLES §3) and reference the
SGNT ticket.

**A release does not deploy.** Merging the release PR tags, builds, attaches
the binary, and dispatches `signet-released` to construct-server, where that
dispatch only *announces* (`deploy-signet`: `announce` ✓, `deploy` skipped).
Prod is a pin, `SIGNET_VERSION` in construct-server's `versions-host.env`, and
moves only when **Promote / Rollback a Version** (service `signet`) commits it;
that push runs the deploy behind the `signet-prod` gate — a second, un-notified
approval after `production-promote`, so a promote can be approved and its pin
committed while prod still waits. After a release the version is *available*,
not live, and after a promote it may not be live yet either;
`curl 127.0.0.1:4010/healthz` says which (v1.9.2 and v1.9.3 both shipped while
prod stayed on v1.9.1, SGNT-52).
