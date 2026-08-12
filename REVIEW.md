# Review instructions

Review-only guidance, higher priority than any `CLAUDE.md`. That file describes
how this repo works; this one describes what a review of it is *for*.

## What this review is for

Signet's CI is narrow and fast:

| job | proves |
|---|---|
| `ci.yml` / `test` | `gofmt -l`, `go vet`, `go test -race ./...`, and that the static binary builds |

Assume that passed. It is worth knowing exactly how little that tells you here:
it proves the code compiles, is formatted, and that the tests it has agree with
it. It proves nothing about whether those tests assert the right thing, and
nothing about the properties below — none of which a Go test observes.

So the review's job is the classes of defect this repo keeps shipping *past* a
green suite. Every one of these was found by review, after CI passed:

**A fix applied at a call site instead of at the layer that owns the
invariant.** This is the single most repeated defect here. A guarantee is
established in one function, the other callers are missed, and the code now
claims a property it does not have. Instances: three readers went straight to
`CurrentVersion` while `resolve` was documented as the single read path; the
provenance column was written by `set` but not by `import`; a mint guard was
added to `generate` while `set --generate` performed the identical write
unguarded; a refusal was extracted for the CLI while the API kept its own copy.

> When a change adds a guard, a normalization, or a required step, ask **which
> layer owns that invariant** and whether every path through it is covered.
> `grep` for the other callers. If the answer is "the caller must remember",
> that is a finding — say what would make it unrepresentable instead.

**A comment that asserts a property the code does not have.** Four instances.
Doc comments here are unusually load-bearing — they carry reasoning that is not
recoverable from the code — which is exactly why a false one is expensive: it
stops the next reader checking. Treat a comment claiming "every X goes through
Y", "this is the only path", or "this cannot happen" as a claim to verify, not
as context. If the diff adds such a claim, check it.

**Silence where a failure should be loud.** A vault that stops without saying
so, a destination reported "in sync" that was never checked, a rotation that
lands in the vault and not at the destination, a value that renders empty
because an input was missing. The recurring shape is a path that returns
success because nothing explicitly failed. Ask what this code prints when it
goes wrong, and whether the exit code says so.

## Ticket fidelity — check this first

When a Switchyard ticket is linked, read its description and exit criteria
before the diff, and answer explicitly in the summary:

- Does the implementation satisfy the stated exit criteria, or only the easy
  subset?
- Was a requirement silently dropped, narrowed, or deferred? Deliberate
  departures are fine **when stated** — this repo's PRs are expected to name
  them and say why. An unstated one is a finding.
- Does the PR claim something is verified that the diff does not demonstrate?
  "Added tests" is credible because CI runs them; what it does not tell you is
  whether the test asserts the thing the ticket asked for.

A change that is clean code and wrong scope is a **🔴 Important** finding. Quote
the unmet criterion.

When no ticket is linked, say so in one line and review the diff on its own
terms. Do not invent intent from the branch name.

## Severity

- **🔴 Important** — discloses or destroys credential material, breaks the audit
  chain or its tamper-evidence, lets a value reach a destination it should not,
  leaves a destination holding a stale value silently, or does not do what the
  ticket asked.
- **🟡 Nit** — conventions, clarity, a comment that will mislead. Never blocking.
- **🟣 Pre-existing** — real, not introduced here. At most two per review.

Cap nits at five; beyond that say "plus N similar". A review that buries one
Important finding under twelve nits has failed at its job.

## Always check

**Plaintext never leaves except where it is meant to.** Values leave the vault
in exactly two audited ways — `signet reveal` to stdout, and rendered file
targets — plus the sealed push to GitHub Actions.

- Does a new code path put a decrypted value into an error message, a log line,
  a ledger `Details` field, or an HTTP response? The API returns metadata only.
- Does a new hash of secret material derive from plaintext alone? The README
  states version hashes never do, because a low-entropy credential is otherwise
  brute-forceable from the database. `vault.ValueDigest` is keyed for this
  reason; a bare `sha256` of a value is a finding.

**Every mutation and its ledger entry are one transaction.** `store.Mutate` and
`MutateValue` exist so a change the ledger cannot record does not happen.

- Does new write code call `AppendAudit` separately after a mutation? That is
  the bug `Mutate` was built to remove.
- Does a gate read state through the `Store` handle and then write inside a
  transaction? Reads that decide a write belong on `Mutation`
  (`GetSecretForUpdate`, `CurrentVersionForUpdate`) or the check is advisory.

**Reads of a secret's value go through `internal/resolve`.** One function
answers "what is this secret worth", because a reader that expands a derivation
differently — or not at all — either fails on a secret with no versions or
pushes an empty value.

- Does new code call `CurrentVersion` + `vault.Decrypt` directly? There is one
  legitimate exception in the tree (`clearDerivation`, which asks what is
  *behind* a derivation) and it says so at the call site.

**A derived secret has no value of its own.** It is composed at read time so a
composed value cannot drift from its inputs.

- Does a new write path let a derived secret be set, rotated, or imported over?
- Does a new version write declare its `store.Provenance`? It is required
  precisely so it cannot be forgotten; a caller that passes `Minted` for a value
  that came from outside makes an externally-issued credential rotatable.

**Drift is reported, not assumed.** `GHState` answers "is this destination
current?" and returns `in sync` by default.

- Does a new state path reach `GHState` with neither a version nor a digest?
  That is the most confident possible answer about something nobody checked.

**Agent-reachable surface.** Several verbs are allowlisted for agents
(`generate`, `rotate`, `derive`, `sync`, `target`, and the read-only ones).

- Does a new verb, or a new flag on an existing one, widen what an agent can do
  without a human? A new mutating verb needs an allowlist decision before it
  ships, and nothing prompts for one — `derive` sat outside the rules for a week.
  Flag it in the review.
- Does a destructive path require an explicit flag? `--replace` and
  `--prune` exist because the alternative is unrecoverable.

## Verification bar

Do not report a finding you have not checked against the code. For anything
turning on a code path, read the path. For anything turning on a claim in a
comment or PR body, verify the claim — several findings here have been that the
claim itself was false.

Where a probe is cheap, run it: this repo builds fast, and `go test -run X
-count=20` settles a flakiness question that reasoning will not.

## Re-reviews

When a PR has been reviewed before, check the previous findings were addressed
**at the layer, not at the instance** — see the first defect class above. Two of
this repo's review rounds found that a fix for a finding had been applied to one
caller and left the others, and one found that the fix re-created the original
bug inside its own error branch.

## Summary shape

Lead with ticket fidelity. Then findings, most severe first, each with the file,
the concrete failure it causes, and what would fix it. Close with what you
checked and could not fault — a review that lists only problems does not tell
the reader what has been examined.
