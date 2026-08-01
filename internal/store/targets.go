package store

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Target is a destination a secret (or a project's secrets) is delivered to.
type Target struct {
	ID                  string
	Kind                string // "file" | "gh-actions"
	SecretID            string // gh-actions targets
	Project             string // file targets
	Config              string // JSON: FileConfig or GHConfig
	LastPushedVersionID string
	LastPushedAt        string
	// LastState is what the last push recorded: never | in sync | error.
	// "drift" is NOT stored — see GHState, which derives it.
	LastState string
	LastError string
	CreatedAt string
}

// FileConfig is the config payload of a kind=file target.
type FileConfig struct {
	Path string   `json:"path"`
	Keys []string `json:"keys"`
	Mode string   `json:"mode"`
}

// GHConfig is the config payload of a kind=gh-actions target.
type GHConfig struct {
	Repo       string `json:"repo"`        // owner/name
	SecretName string `json:"secret_name"` // destination Actions secret
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

// GHState derives a gh-actions target's sync state against the secret's current
// version. It is derived rather than stored: last_state only ever records what
// the last push did ("in sync" / "error", or the "never" default), so drift —
// the vault moving on while the destination keeps an older version — is
// invisible to it. Any view that answers "is this destination current?" has to
// compute it.
func (t *Target) GHState(cur *Version) string {
	switch {
	case t.LastError != "":
		return "error"
	case t.LastPushedAt == "":
		return "never"
	case cur != nil && t.LastPushedVersionID != cur.ID:
		return "drift" // vault moved on; destination holds an old version
	default:
		return "in sync"
	}
}

const targetCols = `id, kind, COALESCE(secret_id, ''), COALESCE(project, ''), config,
    COALESCE(last_pushed_version_id, ''), COALESCE(last_pushed_at, ''), last_state, COALESCE(last_error, ''), created_at`

func (s *Store) queryTargets(where string, args ...any) ([]Target, error) {
	rows, err := s.db.Query(`SELECT `+targetCols+` FROM targets `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("query targets: %w", err)
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.Kind, &t.SecretID, &t.Project, &t.Config,
			&t.LastPushedVersionID, &t.LastPushedAt, &t.LastState, &t.LastError, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan target: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
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

// UpsertFileTarget creates a project file target for path, or merges keys into
// an existing target for the same path. Keys are kept sorted and deduplicated.
func (s *Store) UpsertFileTarget(project, path string, keys []string, mode string) (*Target, error) {
	existing, err := s.FileTargetsForProject(project)
	if err != nil {
		return nil, err
	}
	for i := range existing {
		cfg, err := existing[i].FileConfig()
		if err != nil {
			return nil, err
		}
		if cfg.Path != path {
			continue
		}
		cfg.Keys = mergeKeys(cfg.Keys, keys)
		if mode != "" {
			cfg.Mode = mode
		}
		raw, _ := json.Marshal(cfg)
		if _, err := s.db.Exec(`UPDATE targets SET config = ? WHERE id = ?`, string(raw), existing[i].ID); err != nil {
			return nil, fmt.Errorf("upsert file target: %w", err)
		}
		existing[i].Config = string(raw)
		return &existing[i], nil
	}
	if mode == "" {
		mode = "0600"
	}
	cfg := FileConfig{Path: path, Keys: mergeKeys(nil, keys), Mode: mode}
	raw, _ := json.Marshal(cfg)
	t := Target{ID: newID(), Kind: "file", Project: project, Config: string(raw), LastState: "never", CreatedAt: now()}
	if _, err := s.db.Exec(`
        INSERT INTO targets (id, kind, project, config, last_state, created_at)
        VALUES (?, 'file', ?, ?, 'never', ?)`, t.ID, project, t.Config, t.CreatedAt); err != nil {
		return nil, fmt.Errorf("upsert file target: %w", err)
	}
	return &t, nil
}

// AddGHTarget attaches a GitHub Actions repo-secret destination to a secret.
func (s *Store) AddGHTarget(secretID, repo, secretName string) (*Target, error) {
	cfg := GHConfig{Repo: repo, SecretName: secretName}
	raw, _ := json.Marshal(cfg)
	t := Target{ID: newID(), Kind: "gh-actions", SecretID: secretID, Config: string(raw), LastState: "never", CreatedAt: now()}
	if _, err := s.db.Exec(`
        INSERT INTO targets (id, kind, secret_id, config, last_state, created_at)
        VALUES (?, 'gh-actions', ?, ?, 'never', ?)`, t.ID, secretID, t.Config, t.CreatedAt); err != nil {
		return nil, fmt.Errorf("add gh target: %w", err)
	}
	return &t, nil
}

// FindGHTarget returns the gh-actions target on secretID delivering to repo
// under secretName, or nil when there is none. (repo, secretName) is what
// uniquely identifies a destination for a given secret — the same pair
// add-target refuses to duplicate.
func (s *Store) FindGHTarget(secretID, repo, secretName string) (*Target, error) {
	targets, err := s.TargetsForSecret(secretID)
	if err != nil {
		return nil, err
	}
	for i := range targets {
		if targets[i].Kind != "gh-actions" {
			continue
		}
		cfg, err := targets[i].GHConfig()
		if err != nil {
			return nil, err
		}
		if cfg.Repo == repo && cfg.SecretName == secretName {
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
	for i := range targets {
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
func (s *Store) RemoveTarget(id string) error {
	res, err := s.db.Exec(`DELETE FROM targets WHERE id = ?`, id)
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
func (s *Store) UpdateTargetPush(id, state, lastErr, versionID, pushedAt string) error {
	_, err := s.db.Exec(`
        UPDATE targets
        SET last_state = ?, last_error = NULLIF(?, ''),
            last_pushed_version_id = COALESCE(NULLIF(?, ''), last_pushed_version_id),
            last_pushed_at = COALESCE(NULLIF(?, ''), last_pushed_at)
        WHERE id = ?`, state, lastErr, versionID, pushedAt, id)
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
