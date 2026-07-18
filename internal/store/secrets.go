package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Secret is a vault entry's metadata. Values live in secret_versions.
type Secret struct {
	ID        string
	Project   string
	Name      string
	Scope     string
	Status    string
	Generated bool
	ExpiresAt string // RFC3339 date or empty
	CreatedAt string
	UpdatedAt string
}

// Version is one encrypted value of a secret.
type Version struct {
	ID         string
	SecretID   string
	VersionNo  int
	Nonce      []byte
	Ciphertext []byte
	VHash      string
	CreatedBy  string
	CreatedAt  string
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// GetSecret returns the secret for (project, name), or nil if absent.
func (s *Store) GetSecret(project, name string) (*Secret, error) {
	row := s.db.QueryRow(`
        SELECT id, project, name, scope, status, generated, COALESCE(expires_at, ''), created_at, updated_at
        FROM secrets WHERE project = ? AND name = ?`, project, name)
	return scanSecret(row)
}

// GetSecretByID returns the secret with the given id, or nil if absent.
func (s *Store) GetSecretByID(id string) (*Secret, error) {
	row := s.db.QueryRow(`
        SELECT id, project, name, scope, status, generated, COALESCE(expires_at, ''), created_at, updated_at
        FROM secrets WHERE id = ?`, id)
	return scanSecret(row)
}

func scanSecret(row *sql.Row) (*Secret, error) {
	var sec Secret
	var generated int
	err := row.Scan(&sec.ID, &sec.Project, &sec.Name, &sec.Scope, &sec.Status, &generated, &sec.ExpiresAt, &sec.CreatedAt, &sec.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get secret: %w", err)
	}
	sec.Generated = generated != 0
	return &sec, nil
}

// CreateSecret inserts a new secret row.
func (s *Store) CreateSecret(project, name, scope string, generated bool, expiresAt string) (*Secret, error) {
	sec := Secret{
		ID: newID(), Project: project, Name: name, Scope: scope,
		Status: "active", Generated: generated, ExpiresAt: expiresAt,
		CreatedAt: now(), UpdatedAt: now(),
	}
	gen := 0
	if generated {
		gen = 1
	}
	_, err := s.db.Exec(`
        INSERT INTO secrets (id, project, name, scope, status, generated, expires_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)`,
		sec.ID, sec.Project, sec.Name, sec.Scope, sec.Status, gen, sec.ExpiresAt, sec.CreatedAt, sec.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create secret %s/%s: %w", project, name, err)
	}
	return &sec, nil
}

// ListSecrets returns every secret ordered by project then name.
func (s *Store) ListSecrets() ([]Secret, error) {
	rows, err := s.db.Query(`
        SELECT id, project, name, scope, status, generated, COALESCE(expires_at, ''), created_at, updated_at
        FROM secrets ORDER BY project, name`)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		var sec Secret
		var generated int
		if err := rows.Scan(&sec.ID, &sec.Project, &sec.Name, &sec.Scope, &sec.Status, &generated, &sec.ExpiresAt, &sec.CreatedAt, &sec.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		sec.Generated = generated != 0
		out = append(out, sec)
	}
	return out, rows.Err()
}

// AddVersion appends a new encrypted version for a secret and bumps updated_at.
func (s *Store) AddVersion(secretID string, nonce, ciphertext []byte, vhash, createdBy string) (*Version, error) {
	var next int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version_no), 0) + 1 FROM secret_versions WHERE secret_id = ?`, secretID).Scan(&next); err != nil {
		return nil, fmt.Errorf("add version: %w", err)
	}
	v := Version{
		ID: newID(), SecretID: secretID, VersionNo: next,
		Nonce: nonce, Ciphertext: ciphertext, VHash: vhash,
		CreatedBy: createdBy, CreatedAt: now(),
	}
	if _, err := s.db.Exec(`
        INSERT INTO secret_versions (id, secret_id, version_no, nonce, ciphertext, vhash, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.SecretID, v.VersionNo, v.Nonce, v.Ciphertext, v.VHash, v.CreatedBy, v.CreatedAt); err != nil {
		return nil, fmt.Errorf("add version: %w", err)
	}
	if _, err := s.db.Exec(`UPDATE secrets SET updated_at = ? WHERE id = ?`, now(), secretID); err != nil {
		return nil, fmt.Errorf("add version: %w", err)
	}
	return &v, nil
}

// CurrentVersion returns the newest version of a secret, or nil if none exist.
func (s *Store) CurrentVersion(secretID string) (*Version, error) {
	row := s.db.QueryRow(`
        SELECT id, secret_id, version_no, nonce, ciphertext, vhash, created_by, created_at
        FROM secret_versions WHERE secret_id = ? ORDER BY version_no DESC LIMIT 1`, secretID)
	var v Version
	err := row.Scan(&v.ID, &v.SecretID, &v.VersionNo, &v.Nonce, &v.Ciphertext, &v.VHash, &v.CreatedBy, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("current version: %w", err)
	}
	return &v, nil
}
