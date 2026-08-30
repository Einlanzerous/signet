package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
)

// Target is a destination a secret (or a project's secrets) is delivered to.
type Target struct {
	ID                  string
	Kind                string // "file" | "gh-actions" | "gh-render"
	SecretID            string // gh-actions targets
	Project             string // file and gh-render targets
	Config              string // JSON: FileConfig, GHConfig or GHRenderConfig
	LastPushedVersionID string
	// LastPushedDigest fingerprints the value last delivered, for secrets that
	// have no version to cite — derived ones. Empty for stored secrets, whose
	// drift is answered by the version id above.
	LastPushedDigest string
	LastPushedAt     string
	// LastState is what the last push recorded: never | in sync | error.
	// "drift" is NOT stored — see GHState, which derives it.
	LastState string
	LastError string
	// LastPushedKeys is the JSON key set the last successful push delivered, for
	// gh-render targets. GitHub never reads a secret's value back, so this is
	// signet's only account of what the destination currently holds — and the
	// only basis on which a push that would drop keys can be recognized as one.
	// Empty for every other kind, and for a render target that has never pushed.
	LastPushedKeys string
	CreatedAt      string
}

// PushedKeys decodes LastPushedKeys. A target that has never pushed, or one of
// a kind that does not record a key set, returns nil — which callers must read
// as "no baseline", not as "the last push carried no keys".
func (t *Target) PushedKeys() ([]string, error) {
	if t.LastPushedKeys == "" {
		return nil, nil
	}
	var keys []string
	if err := json.Unmarshal([]byte(t.LastPushedKeys), &keys); err != nil {
		return nil, fmt.Errorf("target %s: bad pushed key set: %w", t.ID, err)
	}
	return keys, nil
}

// FileConfig is the config payload of a kind=file target.
type FileConfig struct {
	Path string   `json:"path"`
	Keys []string `json:"keys"`
	Mode string   `json:"mode"`
}

// GHConfig is the config payload of a kind=gh-actions target, and the GitHub
// half of a kind=gh-render one.
type GHConfig struct {
	Repo       string `json:"repo"`        // owner/name
	SecretName string `json:"secret_name"` // destination Actions secret
	// Environment scopes the secret to a deployment environment. Empty means a
	// repository secret, which is what every target predating this field is.
	//
	// It is not cosmetic: an environment secret lives behind a different API
	// path and is sealed with a different public key, so this field decides
	// which endpoints a push talks to rather than merely how it is labelled.
	Environment string `json:"environment,omitempty"`
}

// GHRenderConfig is the config payload of a kind=gh-render target: a whole
// rendered env file delivered as the value of one GitHub secret.
//
// It carries its own key set rather than borrowing the project's file target's.
// The two are separate destinations that happen to have been seeded from one
// another — a project may keep no file target at all (construct-server is meant
// to end up that way), and a key set that lives on the thing it describes does
// not evaporate when its neighbour is retired.
type GHRenderConfig struct {
	GHConfig
	Keys []string `json:"keys"`
}

// Destination renders a GitHub target's address for display: repo, the
// environment when it has one, and the secret name. One function so that
// `target list`, `status` and the ledger cannot describe the same destination
// three different ways — the environment is precisely the part that, left out,
// makes two different destinations print identically.
func (c GHConfig) Destination() string {
	if c.Environment == "" {
		return c.Repo + " · " + c.SecretName
	}
	return c.Repo + " · " + c.Environment + " · " + c.SecretName
}

// Scope names what a GitHub destination is scoped to, for prose that has to
// distinguish the two ("repository secret" / "environment secret").
func (c GHConfig) Scope() string {
	if c.Environment == "" {
		return "repository secret"
	}
	return "environment secret"
}

// FileConfig decodes the target's config as a FileConfig.
func (t *Target) FileConfig() (FileConfig, error) {
	var c FileConfig
	if err := json.Unmarshal([]byte(t.Config), &c); err != nil {
		return c, fmt.Errorf("target %s: bad file config: %w", t.ID, err)
	}
	return c, nil
}

// GHConfig decodes the target's config as a GHConfig.
func (t *Target) GHConfig() (GHConfig, error) {
	var c GHConfig
	if err := json.Unmarshal([]byte(t.Config), &c); err != nil {
		return c, fmt.Errorf("target %s: bad gh config: %w", t.ID, err)
	}
	return c, nil
}

// GHRenderConfig decodes the target's config as a GHRenderConfig.
func (t *Target) GHRenderConfig() (GHRenderConfig, error) {
	var c GHRenderConfig
	if err := json.Unmarshal([]byte(t.Config), &c); err != nil {
		return c, fmt.Errorf("target %s: bad gh-render config: %w", t.ID, err)
	}
	return c, nil
}

// Manages reports whether the rendered target carries key.
//
// It lives here because the invariant it depends on lives here: every key set
// this package stores is merged and sorted, which is what makes the binary
// search correct. Callers that reimplemented the membership test were each
// asserting that invariant privately, and a linear scan would have kept working
// if it ever broke — silently, in a place that decides what reaches a live
// environment.
func (c GHRenderConfig) Manages(key string) bool { return managesKey(c.Keys, key) }

// Manages reports whether the file target carries key. Same invariant, same
// reason as GHRenderConfig.Manages.
func (c FileConfig) Manages(key string) bool { return managesKey(c.Keys, key) }

func managesKey(keys []string, key string) bool {
	i := sort.SearchStrings(keys, key)
	return i < len(keys) && keys[i] == key
}

// TargetRefused is the last_state a push signet declined to attempt records.
// It is distinct from "error" because the two say different things about the
// destination: an error means a delivery was tried and failed, a refusal means
// nothing was sent at all. See GHState.
const TargetRefused = "refused"

// GHState derives a gh-actions target's sync state. It is derived rather than
// stored: last_state only ever records what the last push did ("in sync" /
// "error", or the "never" default), so drift — the vault moving on while the
// destination keeps an older value — is invisible to it. Any view that answers
// "is this destination current?" has to compute it.
//
// cur is the secret's current version, and digest the fingerprint of a derived
// secret's resolved value; exactly one is meaningful. A derived secret has no
// version, so the version comparison cannot see it move — without the digest
// the switch fell through to "in sync" and stayed there however far its inputs
// travelled, a destination reporting health nobody had checked. See
// vault.ValueDigest.
func (t *Target) GHState(cur *Version, digest string) string {
	// A refusal is a decision signet made locally: nothing was sealed and
	// nothing was sent, so the destination still holds exactly what the last
	// successful push put there. Treating it as an error state would pin the
	// target to "error" until some later sync succeeded, hiding the drift
	// underneath it — and drift is the fact an operator needs, because it is
	// the one that says the deployed environment is stale.
	//
	// That argument stands on its own, and until SGNT-35 it was propped up by a
	// claim that did not: "every view that renders a state renders [LastError]
	// alongside it". None of the CLI views did. A refused push read as ordinary
	// drift in `status`, `target list` and `render --check`, all three true
	// about currency and none of them saying a push had been DECLINED — the
	// fact that explains the drift and the one an operator acts on. The reason
	// was reachable only from `signet audit`, which requires already suspecting
	// a refusal happened.
	//
	// It is true now, for the three states that hide a reason — this one and
	// `unknown`, when LastState is `refused`, and `error`. Three CLI views mark
	// them with a trailing `*` and print the reason: under the table for
	// `signet status` and `signet target list`, beneath the state for `signet
	// render --check`. The fourth, the note at the end of a `render`, prints no
	// state word at all — it is prose — so it carries the reason inline
	// instead. The mirror's TargetView carries LastError as its own field, as
	// it always did.
	//
	// The qualifier is load-bearing and is the whole sentence's honesty, so it
	// is worth saying which states are excluded and why rather than only
	// counting them. LastError outlives the refusal it records — nothing clears
	// it short of a later successful push — so `never` and `in sync` are NOT
	// marked: an operator who fixes a refusal would otherwise see `never*` or
	// `in sync*` still quoting the refusal they just fixed. `unknown` is marked
	// for the opposite reason (SGNT-43): nothing about an unrecorded
	// fingerprint resolves a refusal, so one that landed there — IF a push path
	// ever produces such a row; see the banner in the switch below, which is
	// this comment's own retraction of the shape — would still be in force,
	// while the state word says only that signet cannot tell.
	//
	// `empty` and `incomplete` are not marked and are not decided here at all —
	// renderState answers those two before GHState is reached. Only
	// `render --check` explains them, inline in printRenderCheck; the other
	// views print the bare word. That is SGNT-45, not this.
	//
	// Whoever changes those views owns keeping this list true; it is the
	// justification for the branch below, not decoration on it. The count was
	// wrong for one review round after SGNT-43 made the branch live — the
	// README and stateHidesItsReason were updated and this, the copy that
	// presents the count as the justification, was not. It went wrong a second
	// time because the grep that swept the correction through was tuned to one
	// phrasing and this paragraph used another: when a claim like this changes,
	// grep for the SUBJECT (`unknown`) and read every hit, not for the sentence
	// you remember writing.
	if t.LastError != "" && t.LastState != TargetRefused {
		return "error"
	}
	switch {
	case t.LastPushedAt == "":
		return "never"
	case digest != "":
		// "Is there a fingerprint at all" is asked BEFORE the comparison, and
		// the order is the whole correctness of this branch. A delivery that
		// recorded no fingerprint has an empty LastPushedDigest, so
		// `"" != digest` is trivially true — put the comparison first and every
		// such target reports `drift`, a definite claim that the destination is
		// stale made on the strength of a column nobody wrote. The two tests
		// were in that order until SGNT-43, which made `unknown` dead code and
		// put the wrong answer in its place.
		//
		// Saying "in sync" about it would be the same unchecked claim in the
		// other direction. It is a real state: delivered once, currency unknown
		// until the next push writes a fingerprint.
		//
		// An empty digest here does NOT mean currency is unrecorded. A STORED
		// secret's push records no digest — resolve leaves Resolved.Digest
		// empty for one, since its currency is answered by the version id — so
		// converting that secret with `derive --replace` starts supplying a
		// digest to compare against fingerprints the earlier pushes never
		// wrote. The version id is what says so: PushSecret writes it only when
		// r.Version != nil and PushRender never writes it, so inside this
		// branch — where the secret resolves to a digest and is therefore
		// derived NOW — a non-empty one means the last delivery was of a stored
		// version the vault has since replaced. That is this function's own
		// definition of drift, reached without a digest to compare.
		//
		// ── `unknown` is DEFENSIVE. Nothing writes a row that reaches it. ────
		//
		// Reaching it needs last_pushed_at set with BOTH fingerprint columns
		// empty, and no signet has ever written that combination:
		//
		//   - UpdateTargetPush is the only writer of any last_pushed_* column,
		//     and it sets last_pushed_at only for a non-empty pushedAt.
		//   - Every prov == nil call site is a failure or a refusal, and each
		//     passes pushedAt == "" — so none of them creates the row.
		//   - The success paths always fill one column: resolve.Current returns
		//     a Version or a Digest and never neither, and PushRender's digest
		//     is a ValueDigest, never empty.
		//   - `render`'s file-target loop does pass an empty provenance with a
		//     timestamp — but file targets are answered by fileState, and
		//     GHState is never called on one.
		//
		// Nor is there an archaeology population. Migrations 003 (derivation)
		// and 004 (this column) shipped in the SAME commit, 70afeae (#23), so
		// there was never a signet in which a derived secret existed and the
		// digest column did not; and before it every successful push wrote
		// cur.ID, so every pre-004 row carries a version id. An earlier version
		// of this comment claimed that population, and it does not exist.
		//
		// The branch is kept anyway, and the ordering fixed, because the
		// alternative is answering `drift` — a definite claim — off a column
		// nobody wrote. That is the assumption this function exists to refuse
		// (see the doc above), and a future push path that leaves the digest
		// unwritten would inherit it silently. This is the answer if one ever
		// does. It is not a bug being fixed today.
		if t.LastPushedDigest == "" {
			if t.LastPushedVersionID != "" {
				return "drift"
			}
			return "unknown"
		}
		if t.LastPushedDigest != digest {
			return "drift"
		}
		return "in sync"
	case cur != nil && t.LastPushedVersionID != cur.ID:
		// No emptiness guard here, and that is deliberate — this branch is NOT
		// the mirror of the one above (asked for by the review on #46, and it
		// would have been a regression).
		//
		// An empty version id here is EVIDENCE, not its absence. Reaching this
		// branch means the secret resolves to a version and is therefore stored
		// NOW; the column is cleared only by a push of a DERIVED value, because
		// the provenance branch writes `last_pushed_version_id = NULLIF(?, '')`
		// and a derived push supplies "". So an empty one means the destination
		// holds a composed blob that a `derive --clear` has since replaced with
		// a stored value — the vault has provably moved on, and `drift` is the
		// right answer rather than "signet cannot tell".
		//
		// That is the exact mirror of the narrowing above, one conversion the
		// other way: there a version id proves a stored delivery to a
		// now-derived secret, here an empty one proves a derived delivery to a
		// now-stored secret. Both are drift, and both are reachable.
		return "drift" // vault moved on; destination holds an old version
	default:
		return "in sync"
	}
}

const targetCols = `id, kind, COALESCE(secret_id, ''), COALESCE(project, ''), config,
    COALESCE(last_pushed_version_id, ''), COALESCE(last_pushed_digest, ''), COALESCE(last_pushed_keys, ''),
    COALESCE(last_pushed_at, ''), last_state, COALESCE(last_error, ''), created_at`

func scanTargets(rows *sql.Rows) ([]Target, error) {
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.Kind, &t.SecretID, &t.Project, &t.Config,
			&t.LastPushedVersionID, &t.LastPushedDigest, &t.LastPushedKeys,
			&t.LastPushedAt, &t.LastState, &t.LastError, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan target: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) queryTargets(where string, args ...any) ([]Target, error) {
	ctx, cancel := pooled()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT `+targetCols+` FROM targets `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("query targets: %w", err)
	}
	return scanTargets(rows)
}

// queryTargets reads through the mutation's transaction, so a check made here
// and the write that depends on it cannot be separated by another writer. The
// Store variant reads a snapshot from before the transaction and would reopen
// exactly that gap.
func (m *Mutation) queryTargets(where string, args ...any) ([]Target, error) {
	rows, err := m.tx.Query(`SELECT `+targetCols+` FROM targets `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("query targets: %w", err)
	}
	return scanTargets(rows)
}

// ListTargets returns all targets.
func (s *Store) ListTargets() ([]Target, error) {
	return s.queryTargets(`ORDER BY created_at, id`)
}

// TargetsForSecret returns the gh-actions targets attached to a secret.
func (s *Store) TargetsForSecret(secretID string) ([]Target, error) {
	return s.queryTargets(`WHERE secret_id = ? ORDER BY created_at, id`, secretID)
}

// FileTargetsForProject returns the file targets for a project.
func (s *Store) FileTargetsForProject(project string) ([]Target, error) {
	return s.queryTargets(`WHERE kind = 'file' AND project = ? ORDER BY created_at, id`, project)
}

// RenderTargetsForProject returns the gh-render targets for a project.
func (s *Store) RenderTargetsForProject(project string) ([]Target, error) {
	return s.queryTargets(`WHERE kind = 'gh-render' AND project = ? ORDER BY created_at, id`, project)
}

// RenderTargetsForProject is the tx-scoped listing, for a caller whose write
// depends on which targets exist — see Mutation.FindFileTarget for why the
// Store variant will not do from inside a transaction.
func (m *Mutation) RenderTargetsForProject(project string) ([]Target, error) {
	return m.queryTargets(`WHERE kind = 'gh-render' AND project = ? ORDER BY created_at, id`, project)
}

// RenderTargets returns every gh-render target, in creation order. sync needs
// them across all projects, and asking project by project would mean first
// enumerating projects from the secrets table — a longer route to the same rows
// that silently omits a render target whose project has no secrets left.
func (s *Store) RenderTargets() ([]Target, error) {
	return s.queryTargets(`WHERE kind = 'gh-render' ORDER BY created_at, id`)
}

// UpsertFileTarget creates a project file target for path, or merges keys into
// an existing target for the same path. Keys are kept sorted and deduplicated.
// The returned Outcome distinguishes the two, so the caller's audit entry can
// say which happened.
//
// The read that decides between them and the write that acts on it share this
// transaction. Split apart — as they were when this hung off Store — two
// imports of the same path could both find nothing and both insert, leaving a
// project with two targets for one file and no constraint to catch it.
func (m *Mutation) UpsertFileTarget(project, path string, keys []string, mode string) (*Target, Outcome, error) {
	existing, err := m.queryTargets(`WHERE kind = 'file' AND project = ? ORDER BY created_at, id`, project)
	if err != nil {
		return nil, "", err
	}
	for i := range existing {
		cfg, err := existing[i].FileConfig()
		if err != nil {
			return nil, "", err
		}
		if cfg.Path != path {
			continue
		}
		before := existing[i].Config
		cfg.Keys = mergeKeys(cfg.Keys, keys)
		if mode != "" {
			cfg.Mode = mode
		}
		raw, _ := json.Marshal(cfg)
		if _, err := m.tx.Exec(`UPDATE targets SET config = ? WHERE id = ?`, string(raw), existing[i].ID); err != nil {
			return nil, "", fmt.Errorf("upsert file target: %w", err)
		}
		existing[i].Config = string(raw)
		outcome := OutcomeUpdated
		if string(raw) == before {
			outcome = OutcomeUnchanged
		}
		return &existing[i], outcome, nil
	}
	if mode == "" {
		mode = "0600"
	}
	cfg := FileConfig{Path: path, Keys: mergeKeys(nil, keys), Mode: mode}
	raw, _ := json.Marshal(cfg)
	t := Target{ID: newID(), Kind: "file", Project: project, Config: string(raw), LastState: "never", CreatedAt: now()}
	if _, err := m.tx.Exec(`
        INSERT INTO targets (id, kind, project, config, last_state, created_at)
        VALUES (?, 'file', ?, ?, 'never', ?)`, t.ID, project, t.Config, t.CreatedAt); err != nil {
		return nil, "", fmt.Errorf("upsert file target: %w", err)
	}
	return &t, OutcomeCreated, nil
}

// AddGHTarget attaches a GitHub Actions secret destination to a secret. env is
// the deployment environment to scope the secret to, or "" for a repository
// secret.
func (m *Mutation) AddGHTarget(secretID, repo, env, secretName string) (*Target, error) {
	cfg := GHConfig{Repo: repo, SecretName: secretName, Environment: env}
	raw, _ := json.Marshal(cfg)
	t := Target{ID: newID(), Kind: "gh-actions", SecretID: secretID, Config: string(raw), LastState: "never", CreatedAt: now()}
	if _, err := m.tx.Exec(`
        INSERT INTO targets (id, kind, secret_id, config, last_state, created_at)
        VALUES (?, 'gh-actions', ?, ?, 'never', ?)`, t.ID, secretID, t.Config, t.CreatedAt); err != nil {
		return nil, fmt.Errorf("add gh target: %w", err)
	}
	return &t, nil
}

// AddGHRenderTarget attaches a whole-file rendered destination to a project:
// the project's keys are rendered to env-file content and delivered as the
// value of one GitHub secret.
func (m *Mutation) AddGHRenderTarget(project, repo, env, secretName string, keys []string) (*Target, error) {
	cfg := GHRenderConfig{GHConfig: GHConfig{Repo: repo, SecretName: secretName, Environment: env}, Keys: mergeKeys(nil, keys)}
	raw, _ := json.Marshal(cfg)
	t := Target{ID: newID(), Kind: "gh-render", Project: project, Config: string(raw), LastState: "never", CreatedAt: now()}
	if _, err := m.tx.Exec(`
        INSERT INTO targets (id, kind, project, config, last_state, created_at)
        VALUES (?, 'gh-render', ?, ?, 'never', ?)`, t.ID, project, t.Config, t.CreatedAt); err != nil {
		return nil, fmt.Errorf("add gh-render target: %w", err)
	}
	return &t, nil
}

// AddRenderKeys merges keys into a gh-render target's key set, reporting
// whether anything changed. Keys are kept sorted and deduplicated, as they are
// on a file target.
func (m *Mutation) AddRenderKeys(t *Target, keys []string) (*Target, Outcome, error) {
	cfg, err := t.GHRenderConfig()
	if err != nil {
		return nil, "", err
	}
	before := t.Config
	cfg.Keys = mergeKeys(cfg.Keys, keys)
	raw, _ := json.Marshal(cfg)
	if string(raw) == before {
		return t, OutcomeUnchanged, nil
	}
	if _, err := m.tx.Exec(`UPDATE targets SET config = ? WHERE id = ?`, string(raw), t.ID); err != nil {
		return nil, "", fmt.Errorf("add render keys: %w", err)
	}
	t.Config = string(raw)
	return t, OutcomeUpdated, nil
}

// FindGHTarget returns the gh-actions target on secretID delivering to repo
// under secretName in env, or nil when there is none. (repo, env, secretName)
// is what uniquely identifies a destination for a given secret — the same
// triple add-target refuses to duplicate.
//
// The environment belongs in that key rather than beside it: the same secret
// name in the same repository is a different destination at repository scope
// than it is under an environment, and treating the pair as unique would have
// made attaching the second look like a duplicate of the first.
func (s *Store) FindGHTarget(secretID, repo, env, secretName string) (*Target, error) {
	targets, err := s.TargetsForSecret(secretID)
	if err != nil {
		return nil, err
	}
	return findGHTarget(targets, repo, env, secretName)
}

// FindGHTarget is the tx-scoped lookup. A caller enforcing the uniqueness of
// (repo, env, secretName) must use this rather than the Store variant: checking
// outside the transaction that then inserts leaves a window where another
// writer creates the destination the check just found missing.
func (m *Mutation) FindGHTarget(secretID, repo, env, secretName string) (*Target, error) {
	targets, err := m.queryTargets(`WHERE secret_id = ? ORDER BY created_at, id`, secretID)
	if err != nil {
		return nil, err
	}
	return findGHTarget(targets, repo, env, secretName)
}

func findGHTarget(targets []Target, repo, env, secretName string) (*Target, error) {
	for i := range targets {
		if targets[i].Kind != "gh-actions" {
			continue
		}
		cfg, err := targets[i].GHConfig()
		if err != nil {
			return nil, err
		}
		if cfg.Repo == repo && cfg.Environment == env && cfg.SecretName == secretName {
			return &targets[i], nil
		}
	}
	return nil, nil
}

// FindGHDestination returns any target of either kind already delivering to
// (repo, env, secretName), or nil when the destination is unclaimed.
//
// Uniqueness belongs to the destination rather than to a target kind. One
// GitHub secret is one value, and which kind of signet target writes it is
// invisible from there: a gh-actions target carrying a credential and a
// gh-render target carrying a whole env file PUT the same path, so two of them
// overwrite each other on every sync while each reports "in sync" against its
// own record. Whichever ran last wins, which makes the deployed value a
// function of iteration order.
//
// Tx-scoped only, because its callers insert on the strength of the answer.
func (m *Mutation) FindGHDestination(repo, env, secretName string) (*Target, error) {
	targets, err := m.queryTargets(`WHERE kind IN ('gh-actions', 'gh-render') ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	for i := range targets {
		var cfg GHConfig
		switch targets[i].Kind {
		case "gh-actions":
			c, err := targets[i].GHConfig()
			if err != nil {
				return nil, err
			}
			cfg = c
		default:
			c, err := targets[i].GHRenderConfig()
			if err != nil {
				return nil, err
			}
			cfg = c.GHConfig
		}
		if cfg.Repo == repo && cfg.Environment == env && cfg.SecretName == secretName {
			return &targets[i], nil
		}
	}
	return nil, nil
}

// FindGHRenderTarget returns the project's gh-render target delivering to repo
// under secretName in env, or nil when there is none.
func (s *Store) FindGHRenderTarget(project, repo, env, secretName string) (*Target, error) {
	targets, err := s.RenderTargetsForProject(project)
	if err != nil {
		return nil, err
	}
	return findGHRenderTarget(targets, repo, env, secretName)
}

// FindGHRenderTarget is the tx-scoped lookup, for a caller whose write depends
// on the target existing (or on it not existing yet).
func (m *Mutation) FindGHRenderTarget(project, repo, env, secretName string) (*Target, error) {
	targets, err := m.queryTargets(`WHERE kind = 'gh-render' AND project = ? ORDER BY created_at, id`, project)
	if err != nil {
		return nil, err
	}
	return findGHRenderTarget(targets, repo, env, secretName)
}

func findGHRenderTarget(targets []Target, repo, env, secretName string) (*Target, error) {
	for i := range targets {
		if targets[i].Kind != "gh-render" {
			continue
		}
		cfg, err := targets[i].GHRenderConfig()
		if err != nil {
			return nil, err
		}
		if cfg.Repo == repo && cfg.Environment == env && cfg.SecretName == secretName {
			return &targets[i], nil
		}
	}
	return nil, nil
}

// FindFileTarget returns the project's file target for path, or nil when there
// is none. A project has at most one target per path (UpsertFileTarget merges
// into it rather than adding a second).
func (s *Store) FindFileTarget(project, path string) (*Target, error) {
	targets, err := s.FileTargetsForProject(project)
	if err != nil {
		return nil, err
	}
	return findFileTarget(targets, path)
}

// FindFileTarget is the tx-scoped lookup, for callers whose write depends on the
// target already existing. UpsertFileTarget inserts when it matches nothing, so
// a caller meaning "widen this target" rather than "create one" has to establish
// that inside the same transaction — outside it, a concurrent removal turns the
// upsert into a create.
func (m *Mutation) FindFileTarget(project, path string) (*Target, error) {
	targets, err := m.queryTargets(`WHERE kind = 'file' AND project = ? ORDER BY created_at, id`, project)
	if err != nil {
		return nil, err
	}
	return findFileTarget(targets, path)
}

func findFileTarget(targets []Target, path string) (*Target, error) {
	for i := range targets {
		if targets[i].Kind != "file" {
			continue
		}
		cfg, err := targets[i].FileConfig()
		if err != nil {
			return nil, err
		}
		if cfg.Path == path {
			return &targets[i], nil
		}
	}
	return nil, nil
}

// RemoveTarget detaches a target, so signet stops managing that destination.
//
// It removes only signet's record. Whatever is already at the destination — an
// Actions secret in a GitHub repo, a rendered env file on disk — is left
// exactly as it is; signet simply stops maintaining it. Audit entries that
// reference this target keep their target_id, because the chain is append-only
// and history is not rewritten when a target goes away.
func (m *Mutation) RemoveTarget(id string) error {
	res, err := m.tx.Exec(`DELETE FROM targets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("remove target: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("remove target: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("remove target: no target %s", id)
	}
	return nil
}

// UpdateTargetPush records the outcome of a push attempt.
//
// It stays on Store rather than Mutation because the thing it describes has
// already happened out on the network: the destination holds the new value
// whether or not this row or its ledger entry lands, so there is nothing here
// to roll back. Its audit entry is appended separately and a failure to write
// it is surfaced, not swallowed — see sync.recordPush.
// provenance is what a successful push delivered: the version id it came from,
// or the digest of a derived secret's resolved value. Nil means "leave both
// alone", which is what a failed push wants — it changed nothing, so the record
// of the last successful delivery must survive it.
//
// It is a pointer rather than an empty-string sentinel because those are not
// the same request, and conflating them was a real bug: a derived secret pushes
// with no version id, the empty string was COALESCEd back into keeping the
// previous value, and the target went on citing a version that had nothing to
// do with what was delivered — so drift could never be detected for it.
type PushProvenance struct {
	VersionID string
	Digest    string
	// Keys is the key set a gh-render push delivered. Recorded so the next push
	// can tell a render that has gained keys from one that has quietly lost
	// them; nil for every other kind, which leaves the stored set untouched.
	Keys []string
}

// UpdateTargetPush records a push's outcome on the target row.
func (s *Store) UpdateTargetPush(id, state, lastErr string, prov *PushProvenance, pushedAt string) error {
	ctx, cancel := pooled()
	defer cancel()
	// Written as two statements rather than one with COALESCE tricks: "set
	// these to exactly this" and "leave these as they are" are different
	// updates, and expressing them as one taught the reader that an empty
	// provenance meant "unchanged" when it meant "there isn't one".
	if prov == nil {
		_, err := s.db.ExecContext(ctx, `
        UPDATE targets
        SET last_state = ?, last_error = NULLIF(?, ''),
            last_pushed_at = COALESCE(NULLIF(?, ''), last_pushed_at)
        WHERE id = ?`, state, lastErr, pushedAt, id)
		if err != nil {
			return fmt.Errorf("update target push: %w", err)
		}
		return nil
	}
	// A nil key set leaves the recorded one alone rather than clearing it: only
	// a gh-render push has one to state, and every other kind writing "" would
	// erase the baseline a render target's shrink check depends on.
	keys := ""
	if prov.Keys != nil {
		raw, err := json.Marshal(prov.Keys)
		if err != nil {
			return fmt.Errorf("update target push: %w", err)
		}
		keys = string(raw)
	}
	_, err := s.db.ExecContext(ctx, `
        UPDATE targets
        SET last_state = ?, last_error = NULLIF(?, ''),
            last_pushed_version_id = NULLIF(?, ''),
            last_pushed_digest = ?,
            last_pushed_keys = COALESCE(NULLIF(?, ''), last_pushed_keys),
            last_pushed_at = COALESCE(NULLIF(?, ''), last_pushed_at)
        WHERE id = ?`, state, lastErr, prov.VersionID, prov.Digest, keys, pushedAt, id)
	if err != nil {
		return fmt.Errorf("update target push: %w", err)
	}
	return nil
}

func mergeKeys(a, b []string) []string {
	set := map[string]bool{}
	for _, k := range a {
		set[k] = true
	}
	for _, k := range b {
		set[k] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
