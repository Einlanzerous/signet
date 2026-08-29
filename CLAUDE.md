# CLAUDE.md

How this repo works, and the invariants in force. `REVIEW.md` is higher
priority for a review and describes what a review is *for*; this file describes
the system a review is looking at.

Every invariant below is here because signet broke it at least once. The
citations are the commits that established or restored it — they are the
evidence that the rule is load-bearing rather than a preference, and they are
worth reading when a change looks like it needs an exception.

They cite the **squash commit on `main`**, with its PR number, and not the
branch commit whose subject the text quotes. PRs here are squash-merged, so a
branch commit is reachable only from a merged branch that may be deleted at any
time — `git show` on one fails from a fresh checkout, which is the opposite of
durable evidence. One squash commit therefore sometimes stands for two branch
commits, and the text says which.

## What signet is

A single-host credential vault and sync daemon. Secrets live encrypted in
SQLite; signet fans them out to GitHub Actions secrets, renders them into env
files on disk, and injects them into child processes. It ships as a static Go
binary run under systemd on `imperial-construct` — **no container, no image**
— and Switchyard's delivery reconciler polls its `/healthz` for build identity.

Pure Go, no cgo (`modernc.org/sqlite`). The whole test suite runs in-process.

```
cmd/signet/      the CLI. main.go holds every verb (3.5k lines — SGNT-37
                 tracks splitting it; it is why the reviewer's effort tier
                 is pinned at high). exec.go is the exception, split out.
internal/vault/  crypto: sealing, key derivation, keyed digests, token minting
internal/store/  SQLite, migrations, the hash-chained audit ledger, targets
internal/resolve/ the single read path for "what is this secret worth"
internal/derive/ derived-secret templates
internal/sync/   GitHub push, preflight, drift detection, rendered targets
internal/envfile/ .env parse and merge-render
internal/api/    the HTTP mirror + /healthz
internal/redact/ output redaction for exec --redact
internal/ops/    GitHub token handling, rotation, import
internal/config/ env-var configuration
internal/version/ build identity, stamped at link time
internal/logtest/ test-only: capture what a command logged
```

## The invariants

### 1. Fix at the layer that owns the invariant, not at the call site

This repo's single most repeated defect. A guarantee gets established in one
function, the other callers are missed, and the code now claims a property it
does not have.

Instances: three readers went straight to `CurrentVersion` while `resolve` was
documented as the single read path; the provenance column was written by `set`
but not by `import`; a mint guard was added to `generate` while `set --generate`
performed the identical write unguarded; a refusal was extracted for the CLI
while the API kept its own copy.

> When a change adds a guard, a normalization, or a required step, ask which
> layer owns that invariant and whether every path through it is covered.
> `grep` for the other callers. "The caller must remember" is not a design.

Cited: `16a9a59` (#25) — which carries both `put the provenance and mint guards
at the layer that owns them` and `close the rotation and provenance gaps review
found`; `70afeae` (#23) — `route every reader through resolve, and make derived
drift visible`.

### 2. Reads of a secret's value go through `internal/resolve`

`resolve.Current` answers "what is this secret worth, and what is known about
it" for the entire codebase. A reader that expands a derivation differently —
or not at all — fails on a secret with no versions, or pushes an empty value,
or reports a secret it could not resolve as healthy.

Never call `CurrentVersion` + `vault.Decrypt` directly. There is exactly one
legitimate exception in the tree — `clearDerivation`, which asks what is
*behind* a derivation — and it says so at the call site.

`resolve.ErrNoVersion` is a sentinel because callers divide on it: `render` and
`status` skip such a secret, `reveal` and push must fail.

Cited: `70afeae` (#23), which carries both `route every reader through resolve`
and `keep the mirror from calling an unresolvable secret in sync`.

### 3. A mutation and its ledger entry are one transaction

`store.Mutate` and `store.MutateValue` exist so that a change the ledger cannot
record does not happen. New write code that calls `AppendAudit` separately
after a mutation is reintroducing the bug they were built to remove.

A gate that reads state through the `Store` handle and then writes inside a
transaction is advisory, not a gate. Reads that decide a write belong on
`Mutation` — `GetSecretForUpdate`, `CurrentVersionForUpdate`.

The ledger is hash-chained and tamper-evident. Entries carry a typed
`EventKind` and an `ActorRole` supplied by the call site — **never** inferred
by parsing the free-text `Actor` string. `RoleDaemon` and `RoleHealer` are not
declarable by an API caller: they mean "signet did this on its own initiative",
and a forged one would be covered by the chain hash and therefore permanent.

Cited: SGNT-14 (`fix(store): make mutation and audit append atomic`),
`fix(audit): close chain-fork race, role forgery, and status encoding gaps`.

### 4. Plaintext leaves only in audited ways — audited where an investigator looks

Values leave the vault through `reveal`, `exec`, rendered file targets, and the
sealed push to GitHub. Each egress must leave an entry carrying `SecretID`,
because the question the ledger has to answer is *"where has this credential
been"* and it is asked from the credential's side: `signet audit --secret <ref>`.

An entry naming only a `TargetID` leaves that query empty. The same gap has now
been found on three channels independently — SGNT-18 closed it for `reveal`,
SGNT-32 for `exec`, and **SGNT-34 is open** for `render` and rendered-target
sync, both of which still record `TargetID` alone. A rule rediscovered once per
verb is a rule that belongs in one place, which is why it is stated here rather
than at each call site.

**A disclosure of a derived secret is a disclosure of its inputs.** That rule
lives in `auditDerivedInputs` (`cmd/signet/main.go`), not in any one channel
that reads it, because stated per verb it gets restated or forgotten.

Egress channels share `KindSecretReveal` deliberately: an investigator asking
what disclosed a value wants every channel in one answer, and a per-verb kind
would silently halve the result of every existing query.

Also: a decrypted value must never reach an error message, a log line, a ledger
`Details` field, or an HTTP response. The API returns metadata only.

### 5. Hashes of secret material are keyed

`vault.ValueDigest` is an HMAC, not a bare `sha256`, because a low-entropy
credential is otherwise brute-forceable straight out of the database. A plain
hash of a value is a defect regardless of where it appears.

### 6. Silence where a failure should be loud is the recurring failure shape

The pattern is a path that returns success because nothing explicitly failed:

- a vault daemon that stopped without saying so (SGNT-19 — two multi-day
  outages, invisible because the exit logged nothing)
- a destination reported "in sync" that was never checked
- a credential lookup that found nothing and named none of the paths it tried
  (SGNT-9)
- a preflight that probed the read and let the write fail later (SGNT-29)
- a render that succeeded while leaving the environment holding values the file
  no longer had (SGNT-20)

Ask of any new path: what does this print when it goes wrong, and does the exit
code say so? `render --check` returns non-zero specifically so a deploy script
can gate on it.

### 7. State is reported, not assumed — in either direction

`GHState` answers "is this destination current?" and defaults to `in sync`.
Reaching it with neither a version nor a digest produces the most confident
possible answer about something nobody checked.

The opposite failure is equally real and was shipped: `render` reported every
rendered target "now stale" *unconditionally*, so the warning was wrong
whenever things were fine — and a warning that cries wolf is one operators
learn to skip, including on the run where it is right (SGNT-31).

The three commands that answer "is this destination current?" — `status`,
`render --check`, and `render`'s trailing note — route through one function
(`renderState`) so they cannot come to disagree.

### 8. A derived secret has no value of its own

It is composed at read time so a composed value cannot drift from its inputs.
No write path may let a derived secret be `set`, rotated, or imported over.

Every version write declares its `store.Provenance`. It is required rather than
defaulted precisely so it cannot be forgotten: passing `Minted` for a value
that came from outside makes an externally-issued credential rotatable.

### 9. Build identity is never guessed

`internal/version` reports what this build honestly is: bare semver with **no
`v` prefix**, or the literal `"dev"`, plus the full 40-char commit or JSON
`null`. Read both through `version.Get()` — never the package vars directly.

The rule is *blank is not unset*: a linker flag stamped with an empty value
links `""` **over** the default, so the fallback has to live in `Get()`. The
prefix rule is estate-wide: Switchyard compares versions with strict equality.
Never report a plausible semver you did not ship — it lands in the delivery
ledger indistinguishable from a real deploy.

The two injectors are `.github/workflows/release.yml` and the `Makefile`. They
must agree, and the `Makefile` needs `sed 's/^v//'` because `git describe`
returns the tag as written. (See `df2b21d` (#39) for how a `|| echo dev`
fallback outside a subshell silently stopped running: `||` binds to the
pipeline, whose exit status is `sed`'s, so it never fired and VERSION was
empty.)

### 10. Doc comments are load-bearing, so a false one is expensive

Comments here carry reasoning that is not recoverable from the code. That is
the point of them — and it is exactly why a comment asserting a property the
code lacks is a real defect, not a style issue: it stops the next reader
checking. There have been five instances. The most recent is still in the tree:
`GHState`'s doc comment claims "every view that renders a state renders [the
reason] alongside it" as the *justification* for returning `drift` rather than
`error` on a refused push. `LastError` in fact reaches only the mirror's JSON
and `render`'s trailing note — and that note prints it on `error` alone, which
is precisely the state a refusal is not (SGNT-35, open).

Treat "every X goes through Y", "this is the only path", and "this cannot
happen" as claims to verify.

### 11. Agent-reachable surface is a decision, not a default

Several verbs are allowlisted for agents under `Bash(signet <verb>:*)`
(`generate`, `rotate`, `derive`, `sync`, `target`, and the read-only ones).
`reveal` and `exec` are deliberately not.

A new verb, or a new flag widening what an existing one can do without a human,
needs an allowlist decision before it ships — and nothing prompts for one.
`derive` sat outside the rules for a week. Name it in the PR.

Destructive paths require an explicit flag. `--replace` and `--prune` exist
because the alternative is unrecoverable.

## Working in this repo

**Build and test.** `make build`, `make test`, `make fmt`, `make vet`. CI runs
`gofmt -l`, `go vet`, `go test -race ./...`, and a static build. Run the race
detector locally — several bugs here were races.

**Tests are named as sentences** describing the property, not the function:
`TestServeLogsACleanStop`, `TestRenderWriteSaysTheRenderedTargetsWereNotWritten`.
A regression test should be confirmed to fail against the pre-fix code, and its
failure output is worth making *be* the production symptom.

**Commits are conventional** — release-please reads them. `fix:` cuts a patch,
`feat:` a minor. The subject line says what changed and why it matters; the
body carries the reasoning. Reference the SGNT ticket.

**Migrations are append-only** (`internal/store/store.go`, `migrations`),
applied in order and tracked in `schema_migrations`. Never edit a shipped one.

**Releases deploy themselves.** Merging the release PR tags, builds, attaches
the binary, and dispatches `signet-released` to construct-server, which parks
on the `signet-prod` approval gate **with no notification**. An unapproved run
is silently cancelled by the next release. Check after every release.
