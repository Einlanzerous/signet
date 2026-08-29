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
	// The two hops resolve to different kinds of entry, so they are spelled
	// differently — one token for both sent a reader following it off an input
	// row to a per-secret row where they expected the render's own account.
	if got := carriedBy(0); got != "(carrying entry not recorded)" {
		t.Errorf("a failed append cites %q", got)
	}
	if got := carriedBy(42); got != "(carried by #42)" {
		t.Errorf("a real carrying entry cites %q", got)
	}
	if pushCitation(42) == carriedBy(42) {
		t.Error("the two citation kinds are indistinguishable")
	}
}
