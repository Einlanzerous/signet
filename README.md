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
signet sync                                          # seal & push to GitHub Actions
signet render --project lyceum --check               # drift-check the env file
signet status
signet audit --verify
signet serve                                         # HTTP mirror for Switchyard
```

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
  triggers block UPDATE/DELETE; `signet audit --verify` walks the chain).

## GitHub Actions sync

GitHub resolves `${{ secrets.* }}` from its own store — a local vault can never
serve workflows at runtime, so push-sync is the mechanism: fetch the repo
public key, seal with a libsodium-compatible anonymous box, PUT the secret.
Drift is metadata-based (GitHub never returns values): a destination updated
out-of-band after our last push, or missing entirely, counts as drift.

Set `SIGNET_GITHUB_TOKEN` to a fine-grained PAT with *Secrets: read/write* on
the target repos. This is the vault's **root credential** — it cannot itself be
blind, and its expiry should be tracked in the vault like anything else.

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

Commands are *issued to* the daemon; the caller never touches key material.
`X-Signet-Actor: <name>` attributes API actions in the audit chain.

## Configuration

| Env | Default | |
|---|---|---|
| `SIGNET_DB` | `~/.local/share/signet/signet.db` | SQLite database |
| `SIGNET_MASTER_KEY_FILE` | `~/.config/signet/master.key` | hex AES-256 key, 0400 |
| `SIGNET_GITHUB_TOKEN` | *(empty — sync disabled)* | fine-grained PAT |
| `SIGNET_API_TOKEN` | *(required for `serve`)* | mirror bearer token |
| `SIGNET_ADDR` | `127.0.0.1:4010` | API listen address |

## Development

```
make build   # CGO_ENABLED=0 static binary
make test
make vet
```

Pure-Go SQLite (modernc.org/sqlite) — no CGO, cross-compiles cleanly.
