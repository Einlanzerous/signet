package main

import (
	"strings"
	"testing"

	syncpkg "github.com/Einlanzerous/signet/internal/sync"
)

// The bug, at the line that had it. A push that reached GitHub and wrote none
// of its ledger entries printed `  ✓ …` and nothing else — the only trace a
// log.Printf on stderr, which a deploy script is usually redirecting.
//
// The tick is the claim "delivered and accounted for". Half of that was never
// checked.
func TestADeliveredButUnrecordedPushIsNotTicked(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  syncpkg.PushResult
		says []string
	}{
		{
			name: "ledger write failed",
			res:  syncpkg.PushResult{State: "in sync", AuditErr: "database is locked"},
			says: []string{"NOT IN THE LEDGER", "database is locked", "signet audit"},
		},
		{
			name: "target state write failed",
			res:  syncpkg.PushResult{State: "in sync", StateErr: "database is locked"},
			says: []string{"TARGET STATE NOT UPDATED", "database is locked", "currency"},
		},
		{
			// Both, because recordPush attempts them independently and a
			// reader that stopped at the first would report half the damage.
			name: "both",
			res:  syncpkg.PushResult{State: "in sync", AuditErr: "no such table", StateErr: "disk full"},
			says: []string{"NOT IN THE LEDGER", "no such table", "TARGET STATE NOT UPDATED", "disk full"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var recorded bool
			out := captureStdout(t, func() {
				recorded = notePush("csrv/TOKEN → o/r (TOKEN)", &tc.res)
			})

			if recorded {
				t.Error("an unrecorded push was reported as fully recorded, so nothing counts it")
			}
			if strings.Contains(out, "✓") {
				t.Errorf("the push was ticked:\n%s", out)
			}
			if !strings.Contains(out, "DELIVERED, NOT FULLY RECORDED") {
				t.Errorf("the line does not say what happened:\n%s", out)
			}
			// The delivery is still reported. An operator told this failed
			// would re-run a push that has already changed a live environment,
			// and the destination really does hold the new value.
			if !strings.Contains(out, "csrv/TOKEN → o/r (TOKEN)") {
				t.Errorf("the destination is not named:\n%s", out)
			}
			for _, want := range tc.says {
				if !strings.Contains(out, want) {
					t.Errorf("the report does not say %q:\n%s", want, out)
				}
			}
		})
	}
}

// The other half of every marker: one that fires when nothing is wrong is one
// operators learn to skip (SGNT-31). The overwhelming majority of pushes are
// fully recorded and must read exactly as they did.
func TestAFullyRecordedPushIsStillJustATick(t *testing.T) {
	res := syncpkg.PushResult{State: "in sync"}
	var recorded bool
	out := captureStdout(t, func() {
		recorded = notePush("csrv/TOKEN → o/r (TOKEN)", &res)
	})
	if !recorded {
		t.Error("a fully recorded push was counted as unrecorded")
	}
	if !strings.Contains(out, "✓ csrv/TOKEN → o/r (TOKEN)") {
		t.Errorf("a clean push does not read as one:\n%s", out)
	}
	if strings.Contains(out, "NOT FULLY RECORDED") || strings.Contains(out, "!") {
		t.Errorf("a clean push was qualified:\n%s", out)
	}
}

// An out-of-band reconciliation note describes the DELIVERY, which happened
// under both outcomes. Printing it only beside a tick would drop it in the one
// case where the operator is already being told something went wrong.
func TestTheOutOfBandNoteSurvivesAnUnrecordedPush(t *testing.T) {
	const note = "destination changed out-of-band since last push — re-sealing"
	for _, tc := range []struct {
		name string
		res  syncpkg.PushResult
	}{
		{"recorded", syncpkg.PushResult{State: "in sync", Note: note}},
		{"unrecorded", syncpkg.PushResult{State: "in sync", Note: note, AuditErr: "boom"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() { notePush("csrv/TOKEN → o/r (TOKEN)", &tc.res) })
			if !strings.Contains(out, note) {
				t.Errorf("the reconciliation note was dropped:\n%s", out)
			}
		})
	}
}

// The two decisions SGNT-44 asked to be made rather than inherited: what the
// summary says, and what the process exits with.
func TestSyncVerdictSeparatesUndeliveredFromUnrecorded(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		pushed, failed, unrecorded int
		wantCode                   int
		wantIn                     []string
		wantNotIn                  []string
	}{
		{
			name:   "everything landed and was recorded",
			pushed: 4, wantCode: 0,
			wantIn: []string{"4 pushed, 0 failed"},
			// The count appears only when it is non-zero: a permanent ", 0 not
			// fully recorded" trains the eye to skip the position where the
			// number matters.
			wantNotIn: []string{"not fully recorded"},
		},
		{
			name:   "a transport failure",
			pushed: 3, failed: 1, wantCode: 1,
			wantIn: []string{"3 pushed, 1 failed"},
		},
		{
			// The case this ticket is about. Non-zero, because a deploy script
			// has no other way to notice — and NOT 1, because the two demand
			// opposite responses: a transport failure means the destination
			// does not have the value, this means it does.
			name:   "everything landed, one not recorded",
			pushed: 4, unrecorded: 1, wantCode: exitUnrecorded,
			wantIn: []string{"4 pushed, 0 failed, 1 not fully recorded"},
		},
		{
			// Precedence. Something not reaching its destination is the more
			// urgent fact, and its response — stop the deploy — is right for
			// both. The summary still names the unrecorded count, and the
			// report above names each case individually.
			name:   "both",
			pushed: 2, failed: 1, unrecorded: 1, wantCode: 1,
			wantIn: []string{"2 pushed, 1 failed, 1 not fully recorded"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summary, code := syncVerdict(tc.pushed, tc.failed, tc.unrecorded)
			if code != tc.wantCode {
				t.Errorf("exit code %d, want %d (summary: %q)", code, tc.wantCode, summary)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(summary, want) {
					t.Errorf("summary %q does not contain %q", summary, want)
				}
			}
			for _, unwanted := range tc.wantNotIn {
				if strings.Contains(summary, unwanted) {
					t.Errorf("summary %q contains %q", summary, unwanted)
				}
			}
		})
	}
}

// The exit code is the whole deliverable for a deploy script, so the thing that
// must not quietly change is that it is distinct from both of the codes that
// already mean something.
func TestTheUnrecordedExitCodeIsItsOwn(t *testing.T) {
	if exitUnrecorded == 0 {
		t.Fatal("an unrecorded push exits clean, which is the bug")
	}
	if exitUnrecorded == 1 {
		t.Fatal("an unrecorded push is indistinguishable from a transport failure, " +
			"so a deploy script cannot tell 'the environment is not ready' from " +
			"'the environment is ready but signet's record of it is not'")
	}
	// 2 is `signet`'s unknown-command status (see main).
	if exitUnrecorded == 2 {
		t.Fatal("the unrecorded status collides with the usage error status")
	}
}

// `rotate`'s summary in the mixed case, which is the one place the exit code
// cannot carry the distinction: an undelivered destination makes the command
// exit 1, exactly as it does for `sync`, so the sentence is the only thing left
// to say that some of the pushes that DID land were not recorded.
//
// Found by the reviewer on #48: `pushed` counts a delivered-but-unrecorded push
// as a success — correctly, the destination has the value — so stating it
// unqualified here would put back the unmarked tick notePush removes one line
// up, and make the two verbs disagree about whether the case is worth counting.
func TestRotateHeadlineCountsUnrecordedPushesInTheMixedCase(t *testing.T) {
	// The ordinary failure: nothing unrecorded, so nothing extra is said.
	plain := rotateHeadline(1, 2, 0)
	if !strings.Contains(plain, "1 destination(s) did not receive the new value") {
		t.Errorf("the undelivered count is missing: %q", plain)
	}
	if strings.Contains(plain, "not fully recorded") {
		t.Errorf("a clean fan-out was qualified: %q", plain)
	}

	// The mixed case. `sync`'s summary keeps the count here — pinned by
	// TestSyncVerdictSeparatesUndeliveredFromUnrecorded's "both" row — and this
	// is the assertion that stops the two drifting apart.
	mixed := rotateHeadline(1, 2, 1)
	if !strings.Contains(mixed, "1 of them not fully recorded") {
		t.Errorf("the unrecorded count is dropped, so a push that landed unrecorded "+
			"is reported as an unqualified success: %q", mixed)
	}
	// And the old value is still the headline: an undelivered destination is
	// the more urgent fact and must not be displaced by the qualifier.
	if !strings.HasPrefix(mixed, "rotated, but 1 destination(s) did not receive the new value") {
		t.Errorf("the qualifier displaced the undelivered destinations: %q", mixed)
	}
	// PLACEMENT, not just presence. "of them" has to sit beside the count it
	// qualifies — the pushes that SUCCEEDED — or it reads as one of the
	// destinations that failed, which is the opposite destination to
	// investigate. An earlier version of this test asserted only the two checks
	// above, and both are satisfied by any placement between them; the reviewer
	// on #48 found the clause welded onto "the old value is still live there".
	fail := strings.Index(mixed, "the old value is still live there")
	note := strings.Index(mixed, "of them not fully recorded")
	if fail < 0 || note < 0 || note > fail {
		t.Errorf("the unrecorded clause is not beside the succeeded count, so "+
			"\"of them\" takes the failed destinations as its antecedent: %q", mixed)
	}
	if !strings.Contains(mixed, "2 push(es) succeeded, 1 of them not fully recorded") {
		t.Errorf("the clause is not attached to the count it qualifies: %q", mixed)
	}
}
