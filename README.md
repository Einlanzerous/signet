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
signet set --project construct-server --name API_TOKEN --generate
signet target add --secret construct-server/RELEASE_BOT_PRIVATE_KEY \
    --gh-repo Einlanzerous/purser
signet target list [--secret <p>/<NAME>] [--project <p>]
signet target add-key --project <p> --path </path/.env> --name NAME
signet target rm --secret <p>/<NAME> --gh-repo owner/name   # detach only
signet sync                                          # seal & push to GitHub Actions
signet render --project lyceum --check               # drift-check the env file
signet render --project lyceum                       # write it
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
  each one on the terminal and in the audit entry.
- A file that exists but does not parse is an error, not a rewrite. Signet will
  not overwrite content it could not read.

**Being in the vault and being rendered are different states.** `set` stores a
value; only `import` or `target add-key` records that a file *wants* it. `set`
warns when it writes a key no file target lists, because otherwise the gap is
invisible until someone runs `render --check` by hand.

## The two secret classes

| Class | Example | Model |
|---|---|---|
| **Managed, not blind** | `~/projects/*/.env` dev files | Signet is the registry + renderer + drift detector. The human (and their agents) can read these files — pretending otherwise would be blindness theater. |
| **Blind (future)** | `.env.vault` for the compose stack | Daemon-owned file, mode 0600, separate system user; agents never get read access to a valid injection destination. Lands with the Phase-2 watcher/healer work. |

## Boundary

- **The HTTP API never returns plaintext.** It serves metadata, version hashes
  (`#a3f9c1` = first 6 hex of SHA-256(nonce‖ciphertext) — never derived from
  plaintext alone), sync state, and the audit chain. The Switchyard admin UI is
  a *blind mirror* built on exactly this surface.
- Plaintext leaves the vault in two audited ways only: `signet reveal` (stdout)
  and rendered env-file targets.
- Rotation of externally-issued credentials (GitHub App keys, API keys) is
  human-in-the-loop by design: Signet automates the **fan-out**, not the
  minting. `rotate` only self-serves for `--generate` secrets; everything else
  409s with instructions.
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

Set `SIGNET_GITHUB_TOKEN` to a fine-grained PAT with *Secrets: read/write* on
the target repos. This is the vault's **root credential** — it cannot itself be
blind, and its expiry should be tracked in the vault like anything else. For
convenience, `SIGNET_PAT` is accepted as a fallback when `SIGNET_GITHUB_TOKEN`
is unset, so a vault-managed `SIGNET_PAT` in `.env` can drive `sync` directly.

## HTTP API (Switchyard mirror contract)

Bearer auth (`SIGNET_API_TOKEN`), listens on `SIGNET_ADDR`
(default `127.0.0.1:4010`).

| Route | Purpose |
|---|---|
| `GET /healthz` | liveness (no auth) |
| `GET /v1/mirror/summary` | counts: secrets, projects, target states, audit length, chain verified |
| `GET /v1/mirror/secrets` | full blind registry, grouped by project |
| `GET /v1/mirror/secrets/{project}/{name}` | one secret: metadata, targets + sync state, its audit chain |
| `GET /v1/mirror/audit?limit=n` | newest audit entries + chain verification |
| `POST /v1/commands/sync` | `{project, name}` — seal & push that secret's gh targets |
| `POST /v1/commands/rotate` | `{project, name}` — new version for generated secrets (409 otherwise), then fan-out |
| `POST /v1/commands/add-target` | `{project, name, repo, secret_name?}` — attach a gh-actions target (validated, deduped; run `sync` to push) |
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
| `SIGNET_GITHUB_TOKEN` | *(empty — sync disabled)* | fine-grained PAT (falls back to `SIGNET_PAT`) |
| `SIGNET_API_TOKEN` | *(required for `serve`)* | mirror bearer token |
| `SIGNET_ADDR` | `127.0.0.1:4010` | API listen address |

## Development

```
make build   # CGO_ENABLED=0 static binary
make test
make vet
```

Pure-Go SQLite (modernc.org/sqlite) — no CGO, cross-compiles cleanly.
