package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// AuditEntry is one row of the append-only, hash-chained audit log.
type AuditEntry struct {
	Seq      int64  `json:"seq"`
	TS       string `json:"ts"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	SecretID string `json:"secret_id,omitempty"`
	TargetID string `json:"target_id,omitempty"`
	Details  string `json:"details,omitempty"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// genesisHash seeds the chain before any entries exist.
const genesisHash = "genesis"

func chainHash(prev, ts, actor, action, secretID, targetID, details string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{prev, ts, actor, action, secretID, targetID, details}, "|")))
	return hex.EncodeToString(sum[:])
}

// AppendAudit appends an entry to the chain. Appends are serialized so the
// prev-hash linkage is always built under a total order.
func (s *Store) AppendAudit(actor, action, secretID, targetID, details string) (*AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := genesisHash
	err := s.db.QueryRow(`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("append audit: read chain head: %w", err)
	}
	e := AuditEntry{
		TS: now(), Actor: actor, Action: action,
		SecretID: secretID, TargetID: targetID, Details: details,
		PrevHash: prev,
	}
	e.Hash = chainHash(e.PrevHash, e.TS, e.Actor, e.Action, e.SecretID, e.TargetID, e.Details)
	res, err := s.db.Exec(`
        INSERT INTO audit_log (ts, actor, action, secret_id, target_id, details, prev_hash, hash)
        VALUES (?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?)`,
		e.TS, e.Actor, e.Action, e.SecretID, e.TargetID, e.Details, e.PrevHash, e.Hash)
	if err != nil {
		return nil, fmt.Errorf("append audit: %w", err)
	}
	e.Seq, _ = res.LastInsertId()
	return &e, nil
}

// ListAudit returns the newest entries (descending seq). secretID filters when
// non-empty; limit <= 0 means 50.
func (s *Store) ListAudit(limit int, secretID string) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	where, args := "", []any{}
	if secretID != "" {
		where = "WHERE secret_id = ?"
		args = append(args, secretID)
	}
	args = append(args, limit)
	rows, err := s.db.Query(`
        SELECT seq, ts, actor, action, COALESCE(secret_id, ''), COALESCE(target_id, ''), details, prev_hash, hash
        FROM audit_log `+where+` ORDER BY seq DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.Action, &e.SecretID, &e.TargetID, &e.Details, &e.PrevHash, &e.Hash); err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountAudit returns the number of chain entries.
func (s *Store) CountAudit() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
	return n, err
}

// VerifyAudit walks the whole chain oldest-first, recomputing every hash and
// checking prev-hash linkage. It returns (true, 0, total) when intact, or
// (false, seq, total) identifying the first broken entry.
func (s *Store) VerifyAudit() (bool, int64, int, error) {
	rows, err := s.db.Query(`
        SELECT seq, ts, actor, action, COALESCE(secret_id, ''), COALESCE(target_id, ''), details, prev_hash, hash
        FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return false, 0, 0, fmt.Errorf("verify audit: %w", err)
	}
	defer rows.Close()
	prev := genesisHash
	total := 0
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.Action, &e.SecretID, &e.TargetID, &e.Details, &e.PrevHash, &e.Hash); err != nil {
			return false, 0, total, fmt.Errorf("verify audit: %w", err)
		}
		total++
		if e.PrevHash != prev {
			return false, e.Seq, total, nil
		}
		if chainHash(e.PrevHash, e.TS, e.Actor, e.Action, e.SecretID, e.TargetID, e.Details) != e.Hash {
			return false, e.Seq, total, nil
		}
		prev = e.Hash
	}
	if err := rows.Err(); err != nil {
		return false, 0, total, err
	}
	return true, 0, total, nil
}
