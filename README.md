# Signet

Credential vault and outbound-sync control plane for the Construct (IDEA-13,
first slice). A single static Go binary — CLI + thin HTTP API — that is the
source of truth for the `.env` files scattered across `~/projects` and for the
secrets that must also live off-box (GitHub Actions repo secrets).

Signet is **host-resident**, not part of the docker stack: the vault has to
keep working when the stack is down, which is exactly when you need it. State
is a single SQLite file; crypto is AES-256-GCM under a master key file.

```
signet init                                          # master key + database
signet import --project lyceum ~/projects/lyceum/.env
signet generate --project construct-server --name API_TOKEN   # signet mints it
signet set --project construct-server --name API_TOKEN        # value on stdin
signet rotate --secret construct-server/API_TOKEN             # new value + fan-out
signet target add --secret construct-server/RELEASE_BOT_PRIVATE_KEY \
    --gh-repo Einlanzerous/purser
signet target list [--secret <p>/<NAME>] [--project <p>]
signet target add-key --project <p> --path </path/.env> --name NAME
signet target rm --secret <p>/<NAME> --gh-repo owner/name   # detach only
signet sync --check                                  # can the PAT reach every repo?
signet sync                                          # seal & push to GitHub Actions
signet render --project lyceum --check               # drift-check the env file
signet render --project lyceum                       # write it
signet exec --project lyceum -- ./deploy.sh          # inject; never printed
signet exec --project lyceum --redact -- ./probe.sh  # and filter what comes back
signet status
signet audit --verify
signet serve                                         # HTTP mirror for Switchyard
```

**Detaching a target removes signet's record, nothing else.** `target rm` (and
the mirror's `remove-target`) stop signet managing a destination; the Actions
secret in the repo, or the rendered env file on disk, is left exactly as it is.
Deleting a credential from a repo can break that repo's workflows, and that call
belongs to whoever owns it. Both the CLI and the API say so in their output.
Audit entries naming a removed target keep pointing at it — the chain is
append-only, so history is not rewritten when a target goes away.

**`render` merges; it does not retype the file.** The managed keys get the
vault's current values and every other line survives — comments, blank-line
grouping, key order, and keys signet does not manage. These files are
hand-maintained and gitignored, so anything a canonical rewrite dropped would be
gone with no copy to restore from, and `render` is what you reach for when a file
is *already* in trouble. Two consequences worth knowing:

- A key present in the file but not on the target is **kept**, and both `render`
  and `render --check` name it. `--prune` deletes those keys instead, listing
  each one on the terminal and in the audit entry; `render --check --prune` is
  the dry run for it.
- A file that exists but does not parse is an error, not a rewrite. Signet will
  not overwrite content it could not read, and `--check`, `target list` and
  `status` all report that file as `unreadable` rather than as drift, since
  render is not going to fix it.
- An existing file keeps the mode and ownership it already has; the recorded
  mode applies to a file signet is creating. A `.env` deliberately set to 0640
  for a service group stays that way.
- Multi-line values (PEM keys) are written as literal blocks, not collapsed to
  backslash-escaped single lines, so a rotation does not change a file's format
  out from under `source .env` or compose's `env_file`.

**Being in the vault and being rendered are different states.** `set` stores a
value; only `import` or `target add-key` records that a file *wants* it. `set`
warns when it writes a key no file target lists, because otherwise the gap is
invisible until someone runs `render --check` by hand.

## The two secret classes

| Class | Example | Model |
|---|---|---|
| **Managed, not blind** | `~/projects/*/.env` dev files | Signet is the registry + renderer + drift detector. The human (and their agents) can read these files — pretending otherwise would be blindness theater. |
| **Blind (future)** | `.env.vault` for the compose stack | Daemon-owned file, mode 0600, separate system user; agents never get read access to a valid injection destination. Lands with the Phase-2 watcher/healer work. |

## Minting versus setting, and why they are separate verbs

`signet generate` mints a value and stores it. `signet set` reads one from
stdin. They differ in whether a credential passes through whatever is running
the command, which is the distinction worth gating — and Claude Code's
permission rules match a command **prefix**, so they can gate a verb and cannot
gate a flag:

```
Bash(signet set --generate:*)
  matches  signet set --generate --project p --name N
  misses   signet set --project p --name N --generate
```

A rule whose correctness depends on argument order is not a rule. As separate
verbs, `Bash(signet generate:*)` grants exactly the half that never carries
plaintext inward. `set --generate` still works and does the same thing.

**Minting over an existing value needs `--replace`** — from `generate` *and*
from `set --generate`, since they perform the identical write and a guard one
of them walks around is not a guard. Minting is the case that needs it: the
replaced value is gone and nobody ever saw the new one, so an accidental
overwrite of a live PAT is unrecoverable in a way an accidental `set` — where
you supplied the value — is not. On a secret signet already minted, the message
points at `rotate` instead; that is the operation you almost certainly want,
since it also pushes.

**`signet import` records imported values as externally issued**, so a secret
whose value came from an env file stops being rotatable even if signet minted
an earlier one. The provenance follows the *value*, not the secret.

A write that does not push — `set`, `generate` — warns when the secret (or a
derived secret built on it) has GitHub destinations still holding the previous
value, and names the `sync` commands that fix it.

`signet rotate --secret p/NAME [--expires YYYY-MM-DD] [--no-sync]` mints a
replacement for a secret signet already minted, then pushes it — **and pushes
every derived secret built on it**, since those changed at the same instant and
their own destinations would otherwise keep a value composed from the previous
version.

It refuses externally-issued secrets (signet can fan out a new value, not mint
one) and derived secrets (they have no value of their own — rotate an input),
re-checking both inside the write transaction so the refusal is binding rather
than advisory. `--expires` moves the expiry with the value; without it, an
existing expiry is reported as unchanged rather than left to silently describe
the version this command replaced. A push failure exits non-zero: a rotation
that lands in the vault and not at the destination leaves the old value live
where it is actually used.

## Derived secrets

A secret whose value is **composed from other secrets** holds a template instead
of a value:

```
signet derive --project drydock --name DRYDOCK_DATABASE_URL \
  --from 'postgres://drydock_user:{{construct-server/DRYDOCK_DB_PASSWORD}}@127.0.0.1:5432/drydock'
```

`{{NAME}}` refers to the deriving secret's own project; `{{project/NAME}}`
crosses projects, which the motivating case requires — the password lives in
`construct-server` and the DSN in `drydock`.

**Nothing is stored.** The value is expanded on every render, reveal and sync,
which is the whole point: a composed value that is written down can fall out of
step with what it was composed from. Before this existed, rotating the password
left the DSN silently wrong *and* `render --check` reported both files in sync,
because each entry individually matched what the vault held. The one tool whose
job is noticing divergence structurally could not notice it.

Consequences worth knowing:

- **A derived secret cannot be `set` or rotated.** It has no value of its own.
  Rotate one of its inputs, or change the template with `derive --from`.
  `signet import` skips it for the same reason and says which keys it skipped —
  re-importing a file signet rendered would otherwise store a copy of the
  composed value, which is the drift this exists to prevent.
- **Setting an input names what else just changed**, following chains and
  crossing projects, and which renders to run.
- **`reveal` prints the value on stdout and its provenance on stderr**, so it
  stays pipeable while still answering "where did this come from". It also
  appends an audit entry to **each input's** ledger: revealing a composed value
  discloses its inputs' plaintext, and that has to be recorded where someone
  investigating *that* credential would look.
- **Converting an existing stored secret needs `--replace`.** Its stored value
  may be live somewhere signet cannot see, so discarding it is deliberate. The
  old versions stay in history and stop being read — `derive --clear` puts the
  last one back and makes the secret ordinary again.
- **Drift is tracked by an HMAC of the resolved value**, since there is no
  version to compare. `status` shows `derived #<digest>`, never a version hash:
  a converted secret's old versions are abandoned, and printing one would
  present a value nothing reads as current.
- **A derivation naming no secrets is refused.** That is a constant, which is
  what an ordinary secret already is.
- **Cycles are refused** with the chain that forms them.
- **The template is stored unencrypted**, unlike every value in this database. It
  is a relationship between entries — the same class of metadata as projects,
  names and targets, which the blind mirror already exposes so drift can be
  reasoned about without the master key. Do not put credential material in the
  literal text around the references.

Hashing transforms (`scrypt`, `bcrypt`, `base64`) are **not** implemented;
`derive` composes only. See SGNT-18.

## Running a command with secrets — `signet exec`

```sh
signet exec --project construct-server -- ./deploy.sh
signet exec --secret construct-server/PURSER_CF_API_TOKEN -- ./cf-probe.sh
signet exec --project drydock --redact -- pytest -q
```

The values are resolved, placed in the child's environment keyed by secret
name, and never written to a terminal. `--secret` is repeatable and wins over
`--project` for the same key, which is how one value is swapped out of an
otherwise ordinary project environment.

The invariant this serves is **"plaintext never enters the transcript"** — not
"only certain commands may read secrets". Those are different, and only the
first is achievable: a permission rule matches a tool invocation, not the
processes it spawns, so a script that calls `signet reveal` internally runs
unprompted while the honest direct path is refused. Gating the verb costs the
capability without buying the guarantee. `exec` is the shape that does buy it,
and it is the same one `op run`, `aws-vault exec`, `chamber exec` and
`doppler run` arrived at.

Details worth knowing:

- **A secret that cannot be resolved is an error**, not an omission. The child
  would otherwise start with the variable unset and read it as empty. A secret
  registered but never given a value is skipped by a `--project` sweep, since
  that is absent rather than broken.
- **Injected values override inherited ones.** An inherited variable of the same
  name is the stale copy signet exists to replace.
- **The child's exit code is signet's exit code.** `signet exec -- pytest` is
  asked to run pytest, and a wrapper needs pytest's answer.
- **SIGINT and SIGTERM are forwarded**, so a supervisor or CI cancel does not
  kill the wrapper and orphan the command holding the credentials.
- **Every injection is audited per secret**, under the same event kind as
  `reveal` — including the inputs of a derived secret, whose values it carries.
  `signet audit --secret <input>` shows the disclosure.

## Where plaintext leaves, and what the ledger records

Values leave the vault through `reveal`, `exec`, a rendered file target, the
sealed push to GitHub, and the read of the GitHub PAT itself. **Every one of
them writes an entry carrying the `SecretID`**, because the question the ledger
has to answer is asked from the credential's side — *where has this value been*
— and `signet audit --secret <ref>` filters on exactly that. An entry naming
only a target answers it empty.

A **disclosure of a derived secret is a disclosure of its inputs**, so each
channel also writes against every secret the value was composed from,
transitively and across projects. That rule lives in `internal/disclose`; a new
egress path inherits it rather than restating it.

**Adding a channel means updating three places**, and they are deliberately not
collapsed into one: `internal/disclose`'s list, which is the authoritative
count and the one a maintainer is told to treat as a checklist; the **Boundary**
section above, because that is where the security perimeter is stated and where
the agent-allowlist decision is made; and here. The count went stale in all
three during the change that introduced the fifth and sixth channels, which is
the argument for naming the obligation rather than trusting a cross-reference.

**This makes renders wordy on purpose.** A 95-key render writes 95 per-secret
entries beside its one per-target entry. That is the trade — an entry that is
not *on* the credential is not findable *from* it — but it means the default
`signet audit` (newest 50) can be a page of `secret.render` rows with the
`render` entry they cite pushed off the end. Reach it with `--limit`, or ask
from the side you actually care about:

```
signet audit --secret construct-server/DB_PASSWORD   # where has this been written
signet audit --limit 200                             # the render entry itself
```

### `--redact`

Filters the child's stdout and stderr, replacing any value signet manages with
`«redacted:project/NAME»`:

```
$ signet exec --project construct-server --redact -- ./probe.sh
signet: redacting 96 value(s) from the child's output; 2 shorter than 8 chars are NOT redacted: construct-server/AMBER_TAG, construct-server/DRYDOCK_TAG
Authorization: Bearer «redacted:construct-server/PURSER_CF_API_TOKEN»
```

This flips the guarantee from *"the caller did not echo it"* to *"the stream was
filtered on the way out"*. An accidental `echo $TOKEN`, a curl dumping request
headers on error, a stack trace carrying the environment — all become
non-events. No generic secret tool can do this, because none of them know the
value set.

The filter covers **every value the vault can resolve**, not only what this
invocation injected: a command that reads a credential from a file signet also
manages leaks a value signet knows perfectly well.

**Its limits, which are not incidental:**

- **It bounds accidents, not intent.** `signet exec -- printenv` still exists.
  Redaction matches literal values, so a secret that has been base64'd,
  line-wrapped, or otherwise transformed passes through untouched. Reading
  `--redact` as a boundary against a hostile process would be the same false
  guarantee as the permission rule it replaces.
- **The injected values are visible to other processes.** While the child runs,
  anything running as the same user can read `/proc/<pid>/environ`. That is
  inherent to environment injection and true of every tool in this class, but it
  is worth stating in the agent case, where other commands genuinely do run as
  the same user.
- **Values shorter than 8 characters are not redacted**, and are named on the
  summary line. Redacting `5432` or `true` would replace ordinary text
  throughout the output, and an operator who learns to read past
  `«redacted:…»` will read past the one that mattered.
- **The coverage summary is on stderr**, because on stdout it would corrupt
  anything being piped. So `--redact 2>/dev/null` gives you a filtered stdout
  with no record of what was *not* filtered. If you discard stderr, you discard
  the caveat that qualifies the guarantee.
- **Do not use it when the command's output is the artifact.** The filter
  applies to stdout, so a command whose job is to *produce* a file containing
  credentials will produce one full of placeholders.
- **The child loses its terminal**, since its output goes through a pipe.
  Progress bars, colour, and anything asking `isatty` will behave as though
  redirected. This is why it is a flag rather than the default.

## Boundary

- **The HTTP API never returns plaintext.** It serves metadata, version hashes
  (`#a3f9c1` = first 6 hex of SHA-256(nonce‖ciphertext) — never derived from
  plaintext alone), sync state, and the audit chain. The Switchyard admin UI is
  a *blind mirror* built on exactly this surface.
- Plaintext leaves the vault in five audited ways only: `signet reveal`
  (stdout), `signet exec` (a child process's environment), rendered env-file
  targets, the sealed push to GitHub Actions, and signet's own read of the
  GitHub PAT. Every one records against the credential — see "Where plaintext
  leaves, and what the ledger records" for what that means.
- **Ledger attribution**: CLI writes record `human` unless `SIGNET_ACTOR_ROLE`
  says otherwise. Agents driving allowlisted verbs should set it to
  `rule_engine`, or their changes are indistinguishable from a person's in a
  log whose purpose is saying who acted. Only roles an API caller could declare
  are accepted — `daemon` and `healer` mean signet acted on its own initiative,
  which nothing outside the daemon can honestly assert — and an unusable value
  fails before the command does any work.
- Rotation of externally-issued credentials (GitHub App keys, API keys) is
  human-in-the-loop by design: Signet automates the **fan-out**, not the
  minting. `rotate` only self-serves for secrets signet minted itself
  (`signet generate`); everything else is refused with instructions.
- Every mutation appends to a hash-chained, append-only audit log (SQLite
  triggers block UPDATE/DELETE; `signet audit --verify` walks the chain). Each
  entry is typed — event kind, actor role, structured outcome — and those fields
  are covered by the hash, so they are as tamper-evident as the text beside them.
  The change and its entry share one transaction: a write the ledger cannot
  record does not happen at all.
- Switchyard's own webhook deliveries and rule fires stay in Switchyard's
  Postgres. Signet is a credential vault and control plane, not Switchyard's
  automation log; the `webhook_delivery` / `rule_fire` kinds are for actions the
  **daemon itself** performs.

## GitHub Actions sync

GitHub resolves `${{ secrets.* }}` from its own store — a local vault can never
serve workflows at runtime, so push-sync is the mechanism: fetch the repo
public key, seal with a libsodium-compatible anonymous box, PUT the secret.
Drift is metadata-based (GitHub never returns values): a destination updated
out-of-band after our last push, or missing entirely, counts as drift.

Sync authenticates with a fine-grained PAT holding *Secrets: read/write* on the
target repos. This is the vault's **root credential** — it cannot itself be
blind, and its expiry should be tracked in the vault like anything else.

`sync` resolves it in order, most specific first:

1. `SIGNET_GITHUB_TOKEN` from the environment
2. `SIGNET_PAT` from the environment
3. `signet/SIGNET_PAT` from the vault
4. otherwise it fails, naming all three by name

A variable holding only whitespace carries no credential and falls through to
the next step, including from step 1 to step 2 — a CRLF-terminated line
exported from a `.env` file is not a token, and letting one shadow either the
`SIGNET_PAT` behind it or the vault would spend the run on a 401 that names
neither the variable nor the whitespace in it. This is decided in `config`,
where the two variables collapse into one value, so it holds for `serve` as
much as for `sync`: the daemon is the component actually fed from an env file.

That same collapse is why step 4 recites the whole chain. By the time a resolve
fails, signet genuinely cannot tell which variable was consulted, so naming
only the first would misdirect whoever exported the second.

Step 3 is what keeps the root credential out of the caller's hands: the vault
holds its own PAT like any other secret, so `signet sync` needs no wrapper
arranging the environment first, and nothing has to put the token on a command
line to get it there. The fallback decrypts a credential, so it is recorded in
the ledger as a `secret_reveal` and printed on stderr rather than happening
silently, and a PAT whose expiry day has passed is refused at this seam, with
the date — a dead PAT otherwise arrives as a bare 401 from GitHub. Only
`sync` and the `target add` preflight below read the vault this way; `serve`
still takes its token from the environment. Each read is a `secret_reveal`
entry that states which of the two it was, so an audit of the root credential
can tell a push from a check.

### Environment secrets, and whole-file rendered targets

A GitHub secret can be scoped to a **deployment environment** rather than to the
repository. That is not a label on the same thing: the secret lives behind
`/repos/{owner}/{repo}/environments/{env}/secrets/...` and is sealed with the
*environment's* public key, so sealing against the repository key and PUTting to
the environment path produces a secret GitHub stores and no workflow can read.
`--gh-environment` carries the scope, and everything downstream — the push, the
drift check, the preflight probe — follows it to the right endpoints.

```
signet target add --secret csrv/API_TOKEN --gh-repo owner/name --gh-environment home-server
```

The environment is part of the destination's identity, not a note beside it. The
same secret name in the same repository is one destination at repository scope
and a different one under an environment, so `(repo, environment, secret_name)`
is what `target add` refuses to duplicate.

A **rendered target** (`gh-render`) is the other axis: a whole env file,
delivered as the value of a single secret. It belongs to a project rather than
to one secret, carries its own key set, and is pushed as one atomic blob whose
digest is its drift record.

```
signet target add --project construct-server --render-as-secret \
  --gh-repo Einlanzerous/construct-server \
  --gh-environment home-server --gh-secret PROD_ENV_FILE
```

The key set is **seeded from the project's file target**, not from the whole
project. "Every secret in the project" is wrong in both directions: it carries
keys the environment has never held into it, and it makes every later
`signet set` on that project a silent change to a live environment. Widening
stays an explicit act:

```
signet target add-key --project construct-server --gh-secret PROD_ENV_FILE --name AMBER_TAG
```

#### Why this kind is guarded more heavily than the others

A rendered target is the only destination where **an absent key is invisible**.
GitHub never returns a secret's value, so nothing can diff the destination
against the vault; and the consumer of an env file interpolates a missing key to
the empty string, so a short file deploys a half-configured container rather
than failing. Three production incidents took exactly that shape. Four guards
sit in front of it:

- **A target that manages no keys refuses the push.** The blob it would deliver
  is a complete, well-formed env file containing nothing, which the consumer
  would apply in full — the most destructive thing this code can do, and the one
  the shrink guard below cannot catch, because a first push has no previous
  delivery to compare against.
- **A managed key with no value refuses the whole push.** Not a partial render —
  a shorter env file is still a valid env file, which is precisely the danger.
  `signet render --project <p> --check` reports this as `INCOMPLETE` before a
  sync discovers it.
- **A render that would deliver fewer keys than the last push is refused**, and
  the refusal is recorded in the ledger. Signet's record of what it last sent is
  the only account of what the destination holds. `--allow-shrink` overrides it
  when the removal is deliberate — but only for a run narrowed to one rendered
  target with `--secret`, so the waiver names the environment it is meant for
  rather than covering every target the run happens to touch.
- **`--against` compares the render against a live env file.** This is the only
  guard that covers the *first* push, which has no previous delivery to compare
  with:

```
signet render --project construct-server --check --against /opt/construct-server/.env
```

It names each key the file has and the render lacks — every one of which would
go empty in the deployed environment on the next deploy — and counts the ones it
would add. An empty report is what makes a first push safe.

`--check` **exits non-zero** when it finds anything that would stop a push:
keys that would be dropped, managed keys the vault cannot resolve, or a target
that manages nothing at all. The report is printed in full either way, so the
command is equally usable by eye and as a gate in a deploy script.

`signet sync --check` asks the other half of the question. Reachability is a
property of the credential; completeness is a property of the vault, and a
destination the PAT can write is not the same as a blob there is anything to
write. It renders every target it would push and reports the ones `sync` would
refuse, without sending anything.

One further rule falls out of the two target kinds sharing a destination: **one
GitHub secret can be claimed by only one target.** A `gh-actions` target holding
a credential and a `gh-render` target holding a whole env file write the same
path, so attaching both would make the deployed value depend on which ran last
while each reported itself in sync. `target add` refuses the second one,
whichever kind it is, naming what already holds the destination.

### The repository grant is a manual step, so signet checks it early

The PAT is fine-grained: every new repo must be added to its **repository list**
with *Secrets: read and write* before a push can work. Signet cannot widen its
own grant — that is human-in-the-loop by design — so the most it can do is find
out early and say what to do.

The probe has two halves, because a push needs two grants. It reads the
destination's Actions public key (public material; no secret is sent or
returned), and then asks whether a write would be permitted — by requesting the
deletion of a reserved secret name (`SIGNET_PREFLIGHT_PROBE_DO_NOT_CREATE`).
Authorization is resolved before the resource is looked up, so `403` means the
credential may not write here and `404` means it may. Nothing is created.

The delete is only issued after a read confirms the name is absent, which is
what makes it non-destructive as a property rather than as a likelihood — if
the name *is* present, the probe declines to run and says so instead of
deleting it. On the one path where a delete can still land (the name appearing
between those two calls), the operator is told what was removed rather than
seeing a bare tick.

GitHub's REST documentation lists `204` as the only response for this endpoint
and does not promise the `404`; the behaviour is what the API actually does,
verified across nine live destinations. If that ever changes, the unexpected
status is reported as inconclusive — the only branch that reports write access
is the one that saw the documented-absent answer.

That second half exists because the first cannot stand in for it. Reading a
sealing key needs *Secrets: read*; delivering a value needs write, and at
environment scope those are separate grants on the same token. A rollout once
passed preflight against an environment it could read and `403`'d on the PUT —
`--check` now reports that destination as read-only before you push. A write
probe that is rate-limited or 5xx's is reported as inconclusive rather than
reachable, for the same reason.

`target add` warns if the credential cannot reach the destination. **The target is still added**: attaching a destination and widening
the PAT are two steps in either order, and the check is skippable with
`--no-preflight` or when no credential resolves. `sync --check` does the same
across every destination at once, one probe per *destination* — a repository, or
an environment within one — rather than per secret. An environment cannot be
vouched for by its repository: it has its own key behind its own path, and it
has to already exist, since pushing a secret does not create it. A 404 there is
as likely to mean "no such environment" as "no such grant", and the hint says
so. The mirror's `add-target` reports the same thing as a `preflight` state plus
a `warning` on its success response.

**What a pass proves.** Both grants a push needs: the destination is reachable
and a write to it is permitted. What it does not prove is that the push will
succeed for reasons unrelated to access — the destination can still change
between the check and the push, and preflight is skippable.

A destination that answers reads and refuses writes is reported as `read-only`
and counted as unreachable, because a push to it will 403. A write check that
is rate-limited or 5xx's is reported as inconclusive rather than reachable: the
half that decides whether a push lands is the half that went unanswered.

Adding many destinations at once is better served by `--no-preflight` followed
by one `sync --check`: each add otherwise decrypts the root PAT and writes a
`secret_reveal` entry of its own, and the run-wide check resolves it once.

When a push does fail, the cause leads and the response follows:

```
✗ construct-server/ANTHROPIC_API_KEY → Einlanzerous/argosy: the GitHub credential
  cannot reach Actions Secrets on Einlanzerous/argosy — usually the repository is
  missing from the fine-grained PAT's repository list (Secrets: read and write);
  an archived repo, disabled Actions, or an org SAML/IP policy answers the same 403
  GitHub said: GET /repos/…/actions/secrets/public-key: 403 Forbidden: {"message":…}
```

A 403's own prose ("Resource not accessible by personal access token") is true
and leads nowhere, so it does not lead — but it is never suppressed either, on
the terminal or in the `sync.push.failed` ledger entry, because the grant list
is only the *likeliest* cause of a 403 and someone told to edit a PAT that is
already correct needs the response to work that out.

Throttling is told apart from denial: GitHub answers a secondary rate limit with
403, a non-zero remaining count, and often no `Retry-After`, so the headers are
checked first and the message consulted as a fallback. That fallback can only
downgrade a denial to "inconclusive, retry" — never the reverse — so GitHub
rewording it costs precision, not correctness. Anything inconclusive (rate
limit, 5xx, timeout) is reported as `?` and never fails `sync --check`: it is
not evidence against a grant, and failing on it would make an unrelated GitHub
hiccup indistinguishable from a misconfigured PAT.

## HTTP API (Switchyard mirror contract)

Bearer auth (`SIGNET_API_TOKEN`), listens on `SIGNET_ADDR`
(default `127.0.0.1:4010`).

`SIGNET_ADDR` takes a comma-separated list, because a host serving both
host-local and containerized clients would otherwise have to choose between
them: loopback alone strands every container, and `0.0.0.0` puts a credential
vault on every interface the host has, LAN included. Naming the interfaces is
the middle position —

```
SIGNET_ADDR=127.0.0.1:4010,172.17.0.1:4010   # loopback + the docker bridge
```

— and every address serves the same handler, so a request is identical
whichever one it arrived on. The daemon binds all of them before serving any,
and **refuses to start if any one fails**, naming it. Half-listening is the
failure worth preventing: it answers `/healthz` from the host while refusing
every container, so it looks healthy from the one place that isn't broken. The
startup log states the addresses as actually bound.

`serve` brackets its own lifetime, so the journal can always answer why the
daemon is not running:

```
signet: api listening on 127.0.0.1:4010, 172.17.0.1:4010
signet: received SIGTERM — shutting down
signet: api stopped, released 127.0.0.1:4010, 172.17.0.1:4010
```

Every other way out returns an error, which exits non-zero and says what
happened. A signal exits **0**, deliberately — a deliberate `systemctl stop` is
not a failure — so these two lines are the only record that one arrived. If the
journal shows them with no `Stopping signet.service...` from systemd above them,
something other than systemd signalled the vault.

Hosts must be IP literals. A name is refused, because `net.Listen` resolves it
and binds exactly one of the answers — `localhost:4010` on a dual-stack host
listens on `127.0.0.1` **or** `::1`, so "all of them or none" would hold while
half the clients are turned away. List `127.0.0.1:4010,[::1]:4010` to get both.

> **Listing a Docker address makes Docker a boot dependency.** `172.17.0.1`
> only exists once dockerd has created `docker0`, and refusing to start is the
> whole point of the binding rule — so a unit that wins the race against Docker
> now fails to come up *at all*, including on loopback, where it used to come
> up fine. Order the unit behind Docker, and let it retry:
>
> ```ini
> [Unit]
> Wants=docker.service
> After=docker.service
>
> [Service]
> Restart=always
> RestartSec=5
> ```
>
> `Restart=always`, not `on-failure`: a signalled daemon exits **0**, which
> `on-failure` does not cover, so anything that stops it other than systemd
> leaves it down until a human notices. That is not hypothetical — it is how
> this daemon spent two multi-day windows offline (SGNT-19).
>
> This is the deliberate trade: a vault that is reachable on some interfaces
> and silently not on others is worse than one that is honestly down. Only list
> an address that something else creates if the unit is ordered behind it.

| Route | Purpose |
|---|---|
| `GET /healthz` | liveness (no auth) |
| `GET /v1/mirror/summary` | counts: secrets, projects, target states, audit length, chain verified |
| `GET /v1/mirror/secrets` | full blind registry, grouped by project |
| `GET /v1/mirror/secrets/{project}/{name}` | one secret: metadata, targets + sync state, its audit chain |
| `GET /v1/mirror/audit?limit=n` | newest audit entries + chain verification |
| `POST /v1/commands/sync` | `{project, name}` — seal & push that secret's gh targets |
| `POST /v1/commands/rotate` | `{project, name}` — new version for generated secrets (409 otherwise), then fan-out |
| `POST /v1/commands/add-target` | `{project, name, repo, secret_name?}` — attach a gh-actions target (validated, deduped; run `sync` to push). Reports the grant probe as `preflight` (`ok`/`read-only`/`denied`/`missing`/`rejected`/`unknown`) plus a `warning` whenever the probe has something to report — which includes a probe that passed, since the write check can act |
| `POST /v1/commands/remove-target` | `{project, name, repo, secret_name?}` — detach a gh-actions target; the destination Actions secret is left in place |
| `POST /v1/commands/set-expiry` | `{project, name, expires_at}` — set/clear expiry (`YYYY-MM-DD`, empty clears) |

Commands are *issued to* the daemon; the caller never touches key material.
`X-Signet-Actor: <name>` attributes API actions in the audit chain, and
`X-Signet-Actor-Role: <role>` declares *what kind* of caller it is (see below).
An unrecognized role is a 400 — signet will not guess one. Callers may declare
`human`, `rule_engine`, or `dispatcher`; `daemon` and `healer` are refused,
because they assert that signet acted on its own and no external caller can
truthfully say that.

### Audit entry schema

Each entry carries the free-text `actor` / `action` / `details` it always has,
plus typed fields consumers can render off directly. The typed fields are
**absent** on entries written before this landed, so treat them as optional and
fall back to the free text rather than inferring a value from it.

| Field | |
|---|---|
| `event_kind` | `vault_init` · `secret_write` · `secret_reveal` · `rotation` · `sync_push` · `drift_reconcile` · `render` · `target_config` · `policy_change` · `watcher_event` · `healer_action` · `webhook_delivery` · `rule_fire` |
| `actor_role` | `human` · `rule_engine` · `dispatcher` · `daemon` · `healer` |
| `status` | `{outcome, http_status?, latency_ms?, retried_from?, retried_to?}` |
| `hash_version` | which hashing scheme produced `hash` (see below) |

`outcome` is one of `delivered` · `failed` · `rotated` · `created` · `updated` ·
`unchanged` · `removed` · `verified_healthy` · `auto_resolved` · `reverted` ·
`no_action`.
`http_status` and `latency_ms` are recorded from the actual call, not assumed.
A numeric field is **present iff it was measured** — a push that completed in
under a millisecond reports `"latency_ms": 0`, which is distinct from the field
being absent because no call was made. `retried_from` / `retried_to` are
reserved for retry/recovery transitions; signet does not retry pushes yet, so
they are absent until it does.

`GET /v1/mirror/summary` also reports `healer_actions_7d`, an outcome→count map
over the last seven days. It is aggregated server-side because the audit
endpoint paginates, so counting a window from one page would undercount.
Entries carrying no readable outcome are counted under `unspecified`. The map is
empty until the watcher/healer phase lands.

### Chain versioning

Adding fields to a hash-chained log would invalidate every existing entry if the
hash formula simply changed, so entries record the scheme that produced them.
`hash_version: 1` is the original `"|"`-joined layout; `2` covers the typed
fields and length-prefixes each field so a value containing `|` cannot be
re-split across field boundaries to forge a match. Verification dispatches per
entry, so a vault written before the upgrade keeps verifying, and a v1 row that
somehow carries typed fields is rejected rather than trusted.

## Configuration

| Env | Default | |
|---|---|---|
| `SIGNET_DB` | `~/.local/share/signet/signet.db` | SQLite database |
| `SIGNET_MASTER_KEY_FILE` | `~/.config/signet/master.key` | hex AES-256 key, 0400 |
| `SIGNET_GITHUB_TOKEN` | *(empty — `sync` falls back to the vault)* | fine-grained PAT (env `SIGNET_PAT`, then vault `signet/SIGNET_PAT`) |
| `SIGNET_API_TOKEN` | *(required for `serve`)* | mirror bearer token |
| `SIGNET_ADDR` | `127.0.0.1:4010` | API listen addresses, comma-separated |

## Development

```
make build   # CGO_ENABLED=0 static binary
make test
make vet
```

Pure-Go SQLite (modernc.org/sqlite) — no CGO, cross-compiles cleanly.

**A new verb needs a permission decision before it ships.** Signet is driven by
agents under a `Bash(signet <verb>:*)` allowlist, and nothing prompts for that
decision — `derive` shipped in v1.6.0 and sat outside the rules for a week
before anyone noticed. When adding a `case` to the dispatch switch, say in the
PR whether the verb should be allowlisted and why. The question is not only
"does it mutate": `exec` mutates nothing and discloses plaintext, which is the
property that actually matters.
