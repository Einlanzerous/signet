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
	LastState           string // never | in sync | drift | error
	LastError           string
	CreatedAt           string
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
