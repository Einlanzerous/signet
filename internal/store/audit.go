package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// EventKind classifies what an audit entry records. It is the typed companion
// to the free-text Action string: consumers (the Switchyard mirror) render rich
// rows off the kind and fall back to a generic row when it is absent, so a kind
// must describe the event honestly rather than approximately.
type EventKind string

const (
	// KindVaultInit records the one-time creation of the master key + database.
	KindVaultInit EventKind = "vault_init"
	// KindSecretWrite records a new secret version landing in the vault
	// (set, update, or import).
	KindSecretWrite EventKind = "secret_write"
	// KindSecretReveal records plaintext leaving the vault to a human.
	KindSecretReveal EventKind = "secret_reveal"
	// KindRotation records signet minting a new value for a generated secret.
	KindRotation EventKind = "rotation"
	// KindSyncPush records a fan-out attempt to a gh-actions destination.
	KindSyncPush EventKind = "sync_push"
	// KindRender records a file target being written from the vault.
	KindRender EventKind = "render"
	// KindTargetConfig records a change to where a secret fans out.
	KindTargetConfig EventKind = "target_config"
	// KindPolicyChange records a change to a secret's policy (e.g. expiry).
	KindPolicyChange EventKind = "policy_change"
	// KindDriftReconcile records the daemon correcting a destination that had
	// drifted away from the vault's current version.
	KindDriftReconcile EventKind = "drift_reconcile"
	// KindWatcherEvent records the Docker watcher observing container state.
	// Reserved for the watcher phase (see AppendWatcherEvent).
	KindWatcherEvent EventKind = "watcher_event"
	// KindHealerAction records a remediation the healer performed.
	// Reserved for the healer phase (see AppendHealerAction).
	KindHealerAction EventKind = "healer_action"
	// KindWebhookDelivery records a webhook the daemon itself delivered.
	// Switchyard's own dispatcher deliveries are NOT funnelled through this
	// chain — they live in Switchyard's Postgres by design.
	KindWebhookDelivery EventKind = "webhook_delivery"
	// KindRuleFire records a rule the daemon itself evaluated and fired.
	// As with KindWebhookDelivery, this is not a re-log of Switchyard's rules.
	KindRuleFire EventKind = "rule_fire"
)

var validKinds = map[EventKind]bool{
	KindVaultInit: true, KindSecretWrite: true, KindSecretReveal: true,
	KindRotation: true, KindSyncPush: true, KindRender: true,
	KindTargetConfig: true, KindPolicyChange: true, KindDriftReconcile: true,
	KindWatcherEvent: true, KindHealerAction: true,
	KindWebhookDelivery: true, KindRuleFire: true,
}

// ActorRole is the normalized identity class behind an entry. The free-text
// Actor ("cli:magos", "api:switchyard") stays alongside it for display; the
// role is what consumers may safely key rendering off. It is always supplied by
// the call site — never inferred by parsing the Actor string.
type ActorRole string

const (
	// RoleHuman is a person acting directly (CLI, or the admin UI on their behalf).
	RoleHuman ActorRole = "human"
	// RoleRuleEngine is an automation rule acting without a human in the loop.
	RoleRuleEngine ActorRole = "rule_engine"
	// RoleDispatcher is a delivery worker acting on a queued job.
	RoleDispatcher ActorRole = "dispatcher"
	// RoleDaemon is signet itself acting on a schedule or trigger.
	RoleDaemon ActorRole = "daemon"
	// RoleHealer is the remediation subsystem acting on unhealthy state.
	RoleHealer ActorRole = "healer"
)

var validRoles = map[ActorRole]bool{
	RoleHuman: true, RoleRuleEngine: true, RoleDispatcher: true,
	RoleDaemon: true, RoleHealer: true,
}

// ValidActorRole reports whether role is one signet recognizes. Callers that
// accept a role from outside (the API's role header) must check it here rather
// than passing an arbitrary string into the chain.
func ValidActorRole(role ActorRole) bool { return validRoles[role] }

// ActorRoles lists the recognized roles, sorted, for error messages and docs.
func ActorRoles() []string {
	out := make([]string, 0, len(validRoles))
	for r := range validRoles {
		out = append(out, string(r))
	}
	sort.Strings(out)
	return out
}

// ValidEventKind reports whether kind is one signet recognizes.
func ValidEventKind(kind EventKind) bool { return validKinds[kind] }

// Outcome is the typed result carried by AuditStatus.
type Outcome string

const (
	// OutcomeDelivered means the destination accepted the value.
	OutcomeDelivered Outcome = "delivered"
	// OutcomeFailed means the attempt did not succeed.
	OutcomeFailed Outcome = "failed"
	// OutcomeRotated means a new value was minted.
	OutcomeRotated Outcome = "rotated"
	// OutcomeCreated means a new object was created.
	OutcomeCreated Outcome = "created"
	// OutcomeUpdated means an existing object changed.
	OutcomeUpdated Outcome = "updated"
	// OutcomeUnchanged means the operation was a no-op.
	OutcomeUnchanged Outcome = "unchanged"
	// OutcomeVerifiedHealthy means a check confirmed healthy state.
	OutcomeVerifiedHealthy Outcome = "verified_healthy"
	// OutcomeAutoResolved means a remediation fixed the problem.
	OutcomeAutoResolved Outcome = "auto_resolved"
	// OutcomeReverted means a remediation was rolled back.
	OutcomeReverted Outcome = "reverted"
	// OutcomeNoAction means a check ran and deliberately did nothing.
	OutcomeNoAction Outcome = "no_action"
)

var validOutcomes = map[Outcome]bool{
	OutcomeDelivered: true, OutcomeFailed: true, OutcomeRotated: true,
	OutcomeCreated: true, OutcomeUpdated: true, OutcomeUnchanged: true,
	OutcomeVerifiedHealthy: true, OutcomeAutoResolved: true,
	OutcomeReverted: true, OutcomeNoAction: true,
}

// Healer remediation verbs, used as the Action string on KindHealerAction
// entries so consumers can match an exact token instead of parsing prose.
const (
	// ActionHealerRestart restarts an unhealthy container.
	ActionHealerRestart = "healer.restart"
	// ActionHealerRecreate recreates a container from its declared spec.
	ActionHealerRecreate = "healer.recreate"
	// ActionHealerRollback returns a container to its previous known-good spec.
	ActionHealerRollback = "healer.rollback"
	// ActionHealerEditOwned edits a signet-owned file back to its intended state.
	ActionHealerEditOwned = "healer.edit-owned"
)

// AuditStatus is the structured outcome of an entry, present only where the
// event actually has one. Zero-valued numeric fields are omitted rather than
// reported as 0, so a consumer can distinguish "no latency recorded" from
// "0 ms".
type AuditStatus struct {
	Outcome     Outcome `json:"outcome"`
	HTTPStatus  int     `json:"http_status,omitempty"`
	LatencyMS   int64   `json:"latency_ms,omitempty"`
	RetriedFrom int     `json:"retried_from,omitempty"`
	RetriedTo   int     `json:"retried_to,omitempty"`
}

// AuditEntry is one row of the append-only, hash-chained audit log.
//
// EventKind, ActorRole and Status are absent on entries written before the
// structured-ledger migration; consumers must treat them as optional and fall
// back to the free-text Actor/Action/Details rather than inferring them.
type AuditEntry struct {
	Seq         int64        `json:"seq"`
	TS          string       `json:"ts"`
	Actor       string       `json:"actor"`
	Action      string       `json:"action"`
	SecretID    string       `json:"secret_id,omitempty"`
	TargetID    string       `json:"target_id,omitempty"`
	Details     string       `json:"details,omitempty"`
	EventKind   EventKind    `json:"event_kind,omitempty"`
	ActorRole   ActorRole    `json:"actor_role,omitempty"`
	Status      *AuditStatus `json:"status,omitempty"`
	PrevHash    string       `json:"prev_hash"`
	Hash        string       `json:"hash"`
	HashVersion int          `json:"hash_version"`
}

// AuditRecord is the input to AppendAudit. EventKind and ActorRole are
// required: every event signet records knows what it is and who did it, and
// requiring them here keeps untyped entries from re-entering the chain.
type AuditRecord struct {
	Actor     string
	Action    string
	SecretID  string
	TargetID  string
	Details   string
	EventKind EventKind
	ActorRole ActorRole
	Status    *AuditStatus
}

func (r AuditRecord) validate() error {
	switch {
	case r.Actor == "":
		return errors.New("audit: actor is required")
	case r.Action == "":
		return errors.New("audit: action is required")
	case !validKinds[r.EventKind]:
		return fmt.Errorf("audit: unknown event kind %q", r.EventKind)
	case !validRoles[r.ActorRole]:
		return fmt.Errorf("audit: unknown actor role %q", r.ActorRole)
	}
	if r.Status != nil && !validOutcomes[r.Status.Outcome] {
		return fmt.Errorf("audit: unknown outcome %q", r.Status.Outcome)
	}
	return nil
}

// genesisHash seeds the chain before any entries exist.
const genesisHash = "genesis"

// Hash chain versions. Entries record the version that produced their hash so
// the chain stays verifiable across schema growth: rows written before the
// structured fields existed are still hashed — and re-verified — under v1.
const (
	hashV1      = 1 // ts|actor|action|secret|target|details, "|"-joined
	hashV2      = 2 // length-prefixed, adds event_kind|actor_role|status
	hashCurrent = hashV2
)

// chainHashV1 is the original scheme, retained verbatim so pre-migration
// entries keep verifying. Do not change it.
func chainHashV1(prev, ts, actor, action, secretID, targetID, details string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{prev, ts, actor, action, secretID, targetID, details}, "|")))
	return hex.EncodeToString(sum[:])
}

// chainHashV2 length-prefixes each field instead of joining on a separator.
// With v1's scheme a value containing "|" could be split across the new
// event_kind/actor_role/status boundaries to forge an equivalent hash; a
// length prefix makes the field decomposition unambiguous.
func chainHashV2(fields ...string) string {
	h := sha256.New()
	for _, f := range fields {
		h.Write([]byte(strconv.Itoa(len(f))))
		h.Write([]byte{':'})
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hashFor recomputes an entry's hash under the scheme it was written with.
// statusJSON is the stored encoding, hashed byte-for-byte so an entry stays
// verifiable even if the AuditStatus struct later gains fields.
func hashFor(version int, e *AuditEntry, statusJSON string) string {
	if version == hashV1 {
		return chainHashV1(e.PrevHash, e.TS, e.Actor, e.Action, e.SecretID, e.TargetID, e.Details)
	}
	return chainHashV2(e.PrevHash, e.TS, e.Actor, e.Action, e.SecretID, e.TargetID,
		e.Details, string(e.EventKind), string(e.ActorRole), statusJSON)
}

// encodeStatus renders a status for storage and hashing. Marshalling a struct
// with fixed field order is deterministic, which the hash depends on. A nil
// status encodes as the empty string, not "null".
func encodeStatus(st *AuditStatus) (string, error) {
	if st == nil {
		return "", nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("audit: encode status: %w", err)
	}
	return string(b), nil
}

func decodeStatus(raw string) (*AuditStatus, error) {
	if raw == "" {
		return nil, nil
	}
	var st AuditStatus
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return nil, fmt.Errorf("audit: decode status: %w", err)
	}
	return &st, nil
}

// auditColumns is the read projection shared by every audit query.
const auditColumns = `seq, ts, actor, action, COALESCE(secret_id, ''), COALESCE(target_id, ''),
        details, event_kind, actor_role, status, prev_hash, hash, hash_version`

// scanEntry reads one row of auditColumns, returning the entry alongside the
// raw stored status JSON (which hashing needs byte-exact).
func scanEntry(rows *sql.Rows) (AuditEntry, string, error) {
	var e AuditEntry
	var statusJSON string
	err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.Action, &e.SecretID, &e.TargetID,
		&e.Details, &e.EventKind, &e.ActorRole, &statusJSON, &e.PrevHash, &e.Hash, &e.HashVersion)
	return e, statusJSON, err
}

// AppendAudit appends an entry to the chain. Appends are serialized so the
// prev-hash linkage is always built under a total order.
func (s *Store) AppendAudit(rec AuditRecord) (*AuditEntry, error) {
	if err := rec.validate(); err != nil {
		return nil, err
	}
	statusJSON, err := encodeStatus(rec.Status)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	prev := genesisHash
	err = s.db.QueryRow(`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("append audit: read chain head: %w", err)
	}
	e := AuditEntry{
		TS: now(), Actor: rec.Actor, Action: rec.Action,
		SecretID: rec.SecretID, TargetID: rec.TargetID, Details: rec.Details,
		EventKind: rec.EventKind, ActorRole: rec.ActorRole, Status: rec.Status,
		PrevHash: prev, HashVersion: hashCurrent,
	}
	e.Hash = hashFor(hashCurrent, &e, statusJSON)
	res, err := s.db.Exec(`
        INSERT INTO audit_log (ts, actor, action, secret_id, target_id, details,
                               event_kind, actor_role, status, prev_hash, hash, hash_version)
        VALUES (?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?)`,
		e.TS, e.Actor, e.Action, e.SecretID, e.TargetID, e.Details,
		string(e.EventKind), string(e.ActorRole), statusJSON, e.PrevHash, e.Hash, e.HashVersion)
	if err != nil {
		return nil, fmt.Errorf("append audit: %w", err)
	}
	e.Seq, _ = res.LastInsertId()
	return &e, nil
}

// AppendWatcherEvent records a container-state observation from the Docker
// watcher. The watcher is a later phase of the project; this is the entry point
// it uses so its observations land in the same tamper-evident chain as every
// other signet event rather than in a side log.
func (s *Store) AppendWatcherEvent(actor, action, details string, st *AuditStatus) (*AuditEntry, error) {
	return s.AppendAudit(AuditRecord{
		Actor: actor, Action: action, Details: details,
		EventKind: KindWatcherEvent, ActorRole: RoleDaemon, Status: st,
	})
}

// AppendHealerAction records a remediation the healer performed. action should
// be one of the ActionHealer* verbs, and outcome distinguishes a remediation
// that stuck (OutcomeAutoResolved) from one that was rolled back
// (OutcomeReverted) — the two counts the healer-actions tile reports.
func (s *Store) AppendHealerAction(actor, action, details string, outcome Outcome) (*AuditEntry, error) {
	return s.AppendAudit(AuditRecord{
		Actor: actor, Action: action, Details: details,
		EventKind: KindHealerAction, ActorRole: RoleHealer,
		Status: &AuditStatus{Outcome: outcome},
	})
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
	rows, err := s.db.Query(`SELECT `+auditColumns+`
        FROM audit_log `+where+` ORDER BY seq DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		e, statusJSON, err := scanEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		if e.Status, err = decodeStatus(statusJSON); err != nil {
			return nil, fmt.Errorf("list audit: seq %d: %w", e.Seq, err)
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

// CountAuditKindSince returns how many entries of kind were appended at or
// after since (an RFC3339 timestamp), grouped by outcome. Entries without a
// status are counted under the empty-string key. It backs "N in the last 7
// days, X auto-resolved, Y reverted" style reporting without pulling the whole
// chain across the wire.
func (s *Store) CountAuditKindSince(kind EventKind, since string) (map[Outcome]int, error) {
	rows, err := s.db.Query(`
        SELECT status, COUNT(*) FROM audit_log
        WHERE event_kind = ? AND ts >= ? GROUP BY status`, string(kind), since)
	if err != nil {
		return nil, fmt.Errorf("count audit kind: %w", err)
	}
	defer rows.Close()
	out := map[Outcome]int{}
	for rows.Next() {
		var statusJSON string
		var n int
		if err := rows.Scan(&statusJSON, &n); err != nil {
			return nil, fmt.Errorf("count audit kind: %w", err)
		}
		st, err := decodeStatus(statusJSON)
		if err != nil {
			return nil, err
		}
		if st == nil {
			out[""] += n
			continue
		}
		out[st.Outcome] += n
	}
	return out, rows.Err()
}

// VerifyAudit walks the whole chain oldest-first, recomputing every hash and
// checking prev-hash linkage. It returns (true, 0, total) when intact, or
// (false, seq, total) identifying the first broken entry.
func (s *Store) VerifyAudit() (bool, int64, int, error) {
	rows, err := s.db.Query(`SELECT ` + auditColumns + ` FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return false, 0, 0, fmt.Errorf("verify audit: %w", err)
	}
	defer rows.Close()
	prev := genesisHash
	total := 0
	for rows.Next() {
		e, statusJSON, err := scanEntry(rows)
		if err != nil {
			return false, 0, total, fmt.Errorf("verify audit: %w", err)
		}
		total++
		if e.PrevHash != prev {
			return false, e.Seq, total, nil
		}
		// An unknown hash version cannot be recomputed, so it cannot be
		// trusted — treat it as broken rather than skipping the check.
		if e.HashVersion != hashV1 && e.HashVersion != hashV2 {
			return false, e.Seq, total, nil
		}
		// A v1 row carrying structured fields was written outside AppendAudit:
		// v1 hashing does not cover them, so they would be unverifiable.
		if e.HashVersion == hashV1 && (e.EventKind != "" || e.ActorRole != "" || statusJSON != "") {
			return false, e.Seq, total, nil
		}
		if hashFor(e.HashVersion, &e, statusJSON) != e.Hash {
			return false, e.Seq, total, nil
		}
		prev = e.Hash
	}
	if err := rows.Err(); err != nil {
		return false, 0, total, err
	}
	return true, 0, total, nil
}
