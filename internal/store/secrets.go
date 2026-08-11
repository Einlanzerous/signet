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
	// Derivation is a template naming the secrets this value is composed from,
	// empty for an ordinary secret. A derived secret has no secret_versions row:
	// its value is expanded at read time, which is what stops a composed value
	// from drifting out of step with its inputs. See internal/derive.
	Derivation string
}

// Derived reports whether this secret's value is computed rather than stored.
func (s Secret) Derived() bool { return s.Derivation != "" }

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
	ctx, cancel := pooled()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
        SELECT id, project, name, scope, status, generated, COALESCE(expires_at, ''), created_at, updated_at, derivation
        FROM secrets WHERE project = ? AND name = ?`, project, name)
	return scanSecret(row)
}

// GetSecretByID returns the secret with the given id, or nil if absent.
func (s *Store) GetSecretByID(id string) (*Secret, error) {
	ctx, cancel := pooled()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
        SELECT id, project, name, scope, status, generated, COALESCE(expires_at, ''), created_at, updated_at, derivation
        FROM secrets WHERE id = ?`, id)
	return scanSecret(row)
}

func scanSecret(row *sql.Row) (*Secret, error) {
	var sec Secret
	var generated int
	err := row.Scan(&sec.ID, &sec.Project, &sec.Name, &sec.Scope, &sec.Status, &generated, &sec.ExpiresAt, &sec.CreatedAt, &sec.UpdatedAt, &sec.Derivation)
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
func (m *Mutation) CreateSecret(project, name, scope string, generated bool, expiresAt string) (*Secret, error) {
	sec := Secret{
		ID: newID(), Project: project, Name: name, Scope: scope,
		Status: "active", Generated: generated, ExpiresAt: expiresAt,
		CreatedAt: now(), UpdatedAt: now(),
	}
	gen := 0
	if generated {
		gen = 1
	}
	_, err := m.tx.Exec(`
        INSERT INTO secrets (id, project, name, scope, status, generated, expires_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)`,
		sec.ID, sec.Project, sec.Name, sec.Scope, sec.Status, gen, sec.ExpiresAt, sec.CreatedAt, sec.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create secret %s/%s: %w", project, name, err)
	}
	return &sec, nil
}

// SetExpiry updates a secret's expiry (RFC3339, or empty to clear) and bumps
// updated_at.
func (m *Mutation) SetExpiry(secretID, expiresAt string) error {
	if _, err := m.tx.Exec(
		`UPDATE secrets SET expires_at = NULLIF(?, ''), updated_at = ? WHERE id = ?`,
		expiresAt, now(), secretID); err != nil {
		return fmt.Errorf("set expiry: %w", err)
	}
	return nil
}

// GetSecretForUpdate reads a secret through the mutation's transaction, so a
// check made on it and the write that depends on it cannot be separated by
// another writer.
//
// The Store variant reads a snapshot taken before the transaction opened, which
// is fine for a report and wrong for a gate: `rotate` refuses derived and
// externally-issued secrets, and both of those facts can change between the
// read and the write. Re-reading here is what makes the refusal binding.
func (m *Mutation) GetSecretForUpdate(id string) (*Secret, error) {
	row := m.tx.QueryRow(`
        SELECT id, project, name, scope, status, generated, COALESCE(expires_at, ''), created_at, updated_at, derivation
        FROM secrets WHERE id = ?`, id)
	return scanSecret(row)
}

// SetGenerated records whether signet minted the secret's current value.
//
// It exists because the column was write-once — CreateSecret was its only
// writer — while the fact it records is a property of the *current value*, not
// of the secret's origin. Overwriting a minted value with one from stdin left
// it reading "signet minted this", so `rotate` would mint over a live
// externally-issued credential; minting over an imported value left it reading
// the opposite, so the value signet had just minted was permanently
// unrotatable. Both directions contradict what rotation promises.
func (m *Mutation) SetGenerated(secretID string, generated bool) error {
	g := 0
	if generated {
		g = 1
	}
	if _, err := m.tx.Exec(
		`UPDATE secrets SET generated = ?, updated_at = ? WHERE id = ?`,
		g, now(), secretID); err != nil {
		return fmt.Errorf("set generated: %w", err)
	}
	return nil
}

// SetDerivation makes a secret derived, or clears it back to an ordinary one
// with the empty string. The caller validates the template; the store only
// records it.
func (m *Mutation) SetDerivation(secretID, derivation string) error {
	if _, err := m.tx.Exec(
		`UPDATE secrets SET derivation = ?, updated_at = ? WHERE id = ?`,
		derivation, now(), secretID); err != nil {
		return fmt.Errorf("set derivation: %w", err)
	}
	return nil
}

// ListSecrets returns every secret ordered by project then name.
func (s *Store) ListSecrets() ([]Secret, error) {
	ctx, cancel := pooled()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, project, name, scope, status, generated, COALESCE(expires_at, ''), created_at, updated_at, derivation
        FROM secrets ORDER BY project, name`)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		var sec Secret
		var generated int
		if err := rows.Scan(&sec.ID, &sec.Project, &sec.Name, &sec.Scope, &sec.Status, &generated, &sec.ExpiresAt, &sec.CreatedAt, &sec.UpdatedAt, &sec.Derivation); err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		sec.Generated = generated != 0
		out = append(out, sec)
	}
	return out, rows.Err()
}

// AddVersion appends a new encrypted version for a secret and bumps
// updated_at. The next version number is read inside the same transaction that
// writes it, so two writers cannot both claim it.
func (m *Mutation) AddVersion(secretID string, nonce, ciphertext []byte, vhash, createdBy string) (*Version, error) {
	var next int
	if err := m.tx.QueryRow(`SELECT COALESCE(MAX(version_no), 0) + 1 FROM secret_versions WHERE secret_id = ?`, secretID).Scan(&next); err != nil {
		return nil, fmt.Errorf("add version: %w", err)
	}
	v := Version{
		ID: newID(), SecretID: secretID, VersionNo: next,
		Nonce: nonce, Ciphertext: ciphertext, VHash: vhash,
		CreatedBy: createdBy, CreatedAt: now(),
	}
	if _, err := m.tx.Exec(`
        INSERT INTO secret_versions (id, secret_id, version_no, nonce, ciphertext, vhash, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.SecretID, v.VersionNo, v.Nonce, v.Ciphertext, v.VHash, v.CreatedBy, v.CreatedAt); err != nil {
		return nil, fmt.Errorf("add version: %w", err)
	}
	if _, err := m.tx.Exec(`UPDATE secrets SET updated_at = ? WHERE id = ?`, now(), secretID); err != nil {
		return nil, fmt.Errorf("add version: %w", err)
	}
	return &v, nil
}

// CurrentVersion returns the newest version of a secret, or nil if none exist.
func (s *Store) CurrentVersion(secretID string) (*Version, error) {
	ctx, cancel := pooled()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
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
