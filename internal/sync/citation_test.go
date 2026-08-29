package sync

import "testing"

// recordPush returns 0 when its append failed, so the citation has to say that
// rather than point at entry 0 — a ledger reference that resolves to nothing,
// on every key of a 95-key render, with the AuditErr that explains it gone
// from everywhere but one terminal.
func TestPushCitationNeverPointsAtEntryZero(t *testing.T) {
	if got := pushCitation(0); got != "(push entry not recorded)" {
		t.Errorf("a failed append cites %q", got)
	}
	if got := pushCitation(42); got != "(push #42)" {
		t.Errorf("a real entry cites %q", got)
	}
}
