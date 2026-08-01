// Package store is signet's embedded persistence layer: a single SQLite
// database (modernc.org/sqlite, pure Go) in WAL mode.
//
// Signet deliberately does not use the construct-server shared Postgres: the
// vault must stay available when the docker stack is down — that is exactly
// when it is needed most — and storing the Postgres credential inside Postgres
// would make cold starts circular.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite handle. The mutex serializes writes within this
// process; the chain's total order across processes comes from the
// immediate-locked transaction each write runs in.
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	// _txlock=immediate takes the write lock at BEGIN rather than at first
	// write. Do not remove it as redundant next to Mutate's explicit
	// transaction — the two are both load-bearing, and neither works alone.
	//
	// Without the transaction, two processes read the same chain head and fork
	// the chain. Without this parameter, the transaction is deferred: it starts
	// SHARED and upgrades to RESERVED at the first write, and two writers
	// holding SHARED deadlock on that upgrade. busy_timeout cannot rescue it,
	// because neither side can make progress by waiting. Stripping either half
	// makes TestConcurrentAppendKeepsChainIntact fail — as a fork, or as
	// SQLITE_BUSY.
	//
	// The driver applies the mode only to write transactions (modernc.org/sqlite
	// tx.go: "begin "+beginMode when !opts.ReadOnly), so reads are unaffected.
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	// SQLite is single-writer; keep the pool at one connection so writes
	// never contend and pragmas apply to every statement.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Mutation is a set of changes in flight inside one transaction. Its methods
// are the write half of the vault — new versions, targets, policy — and they
// hang off this type rather than off Store so that none of them can be reached
// without the audit entry Mutate demands.
//
// It deliberately does not carry the *Store. The pool is capped at one
// connection (see Open), so calling back into a Store method while this
// transaction is open would block waiting for the connection this transaction
// is already holding — a deadlock rather than an error. Reads a mutation
// depends on belong before the Mutate call, or on this type as tx-scoped
// methods of their own.
type Mutation struct {
	tx *sql.Tx
}

// Mutate applies the changes fn makes and the audit entry fn returns to
// describe them, in one transaction: either both land or neither does. It is
// the only way to change vault state, because a mutation this ledger does not
// record is precisely what the ledger exists to make impossible.
//
// fn returns the record instead of receiving one because the record usually
// cannot be written until the change has happened — it names the version number
// or the id the change produced. Anything else the caller needs from inside is
// captured by the closure.
//
// Reading the chain head and writing the entry that links to it happen in this
// same immediate-locked transaction. A mutex alone would not do: it orders
// writers within this process, but the vault is also reachable from CLI
// invocations running beside the daemon, and two processes that read the same
// head both write entries claiming the same prev_hash — a fork the append-only
// triggers make unrepairable.
func (s *Store) Mutate(fn func(*Mutation) (AuditRecord, error)) (*AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("mutate: begin: %w", err)
	}
	defer tx.Rollback()

	rec, err := fn(&Mutation{tx: tx})
	if err != nil {
		return nil, err
	}
	e, err := appendAuditTx(tx, rec)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("mutate: commit: %w", err)
	}
	return e, nil
}

// newID returns a random 128-bit hex identifier.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("store: id entropy unavailable: %v", err))
	}
	return hex.EncodeToString(b)
}

// migrations are applied in order; schema_migrations records progress.
var migrations = []string{
	// 001 — initial schema.
	`
CREATE TABLE secrets (
    id         TEXT PRIMARY KEY,
    project    TEXT NOT NULL,
    name       TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'active',
    generated  INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (project, name)
);

CREATE TABLE secret_versions (
    id         TEXT PRIMARY KEY,
    secret_id  TEXT NOT NULL REFERENCES secrets(id),
    version_no INTEGER NOT NULL,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    vhash      TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (secret_id, version_no)
);

CREATE TABLE targets (
    id                     TEXT PRIMARY KEY,
    kind                   TEXT NOT NULL CHECK (kind IN ('file', 'gh-actions')),
    secret_id              TEXT REFERENCES secrets(id),
    project                TEXT,
    config                 TEXT NOT NULL,
    last_pushed_version_id TEXT,
    last_pushed_at         TEXT,
    last_state             TEXT NOT NULL DEFAULT 'never',
    last_error             TEXT,
    created_at             TEXT NOT NULL
);

CREATE TABLE audit_log (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    secret_id TEXT,
    target_id TEXT,
    details   TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit log is append-only');
END;

CREATE INDEX idx_versions_secret ON secret_versions(secret_id, version_no DESC);
CREATE INDEX idx_targets_secret  ON targets(secret_id);
CREATE INDEX idx_targets_project ON targets(project);
CREATE INDEX idx_audit_secret    ON audit_log(secret_id);
`,
	// 002 — structured audit ledger. All columns default to the empty/legacy
	// value so entries written before this migration stay byte-identical: they
	// keep verifying under hash version 1, and only new entries are hashed with
	// the extended scheme.
	`
ALTER TABLE audit_log ADD COLUMN event_kind   TEXT    NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN actor_role   TEXT    NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN status       TEXT    NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1;

CREATE INDEX idx_audit_kind_ts ON audit_log(event_kind, ts);
`,
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	var current int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	for i := current; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("migrate %d: %w", i+1, err)
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, i+1); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate %d: %w", i+1, err)
		}
	}
	return nil
}
