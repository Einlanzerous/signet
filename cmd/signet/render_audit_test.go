package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/store"
)

// `render` is the egress channel with the longest-lived exposure of the three:
// it leaves plaintext sitting in a file. Until SGNT-34 it recorded only the
// TargetID, so the question asked from the credential's side — `signet audit
// --secret <ref>`, "where has this password been written" — answered empty for
// the one channel that writes it down.
func TestRenderIsAuditedPerSecret(t *testing.T) {
	st := newCLIVault(t)
	path := seedProject(t, st, "csrv", map[string]string{"DB_PASSWORD": "inner-secret-value"})

	captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv"}); err != nil {
			t.Fatal(err)
		}
	})

	entries := renderEntriesFor(t, st, "csrv", "DB_PASSWORD")
	if len(entries) == 0 {
		t.Fatal("a render that wrote a secret's plaintext to disk left no entry on that secret")
	}
	e := entries[0]
	// The path is the fact an investigator came for: knowing a render happened
	// is not the same as knowing which file now holds the value.
	if !strings.Contains(e.Details, path) {
		t.Fatalf("the entry does not name the file the plaintext was written to: %q", e.Details)
	}
	// Shared with reveal and exec so one query answers "what disclosed this
	// value". A kind of its own would silently shorten every existing answer.
	if e.EventKind != store.KindSecretReveal {
		t.Fatalf("event kind = %q, want %q", e.EventKind, store.KindSecretReveal)
	}
	// Both ends, not one: the entry is found from the credential and still
	// leads back to the target whose render wrote it.
	if e.TargetID == "" {
		t.Error("the per-secret entry carries no TargetID, so it cannot be tied back to the render")
	}
	// The per-target entry is kept, not replaced — a deploy script auditing
	// renders reads the target's history and must still find it.
	if !hasRenderTargetEntry(t, st) {
		t.Error("the per-target render entry is gone; the per-secret entries are a second index, not a replacement")
	}
}

// A derived secret has no value of its own — it is composed from others at read
// time — so writing it to disk writes theirs. The same gap SGNT-18 closed for
// `reveal` and SGNT-32 for `exec`, reached through the third channel.
func TestRenderAuditsTheInputsOfADerivedSecret(t *testing.T) {
	st := newCLIVault(t)
	path := seedProject(t, st, "csrv", map[string]string{"DB_PASSWORD": "inner-secret-value"})
	// Composed without spelling a connection string: what is under test is that
	// the input is audited, not the shape of the value that carries it.
	if err := runDerive([]string{"--project", "csrv", "--name", "DSN",
		"--from", "wrapper[{{csrv/DB_PASSWORD}}]wrapper"}); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() {
		if err := runTargetAddKey([]string{"--project", "csrv", "--path", path, "--name", "DSN"}); err != nil {
			t.Fatal(err)
		}
	})

	captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv"}); err != nil {
			t.Fatal(err)
		}
	})

	for _, e := range renderEntriesFor(t, st, "csrv", "DB_PASSWORD") {
		if !strings.Contains(e.Details, "derives from it") {
			continue
		}
		// An investigator who arrives here because this secret is an INPUT has
		// the same question as one who arrives at it directly, so the entry has
		// to lead back the same way: to the target, and one level up the chain.
		if e.TargetID == "" {
			t.Error("an input's entry carries no TargetID, so it cannot be tied back to the render")
		}
		// The NUMBER, not the prefix. `(carried by #N)` and `(render #N)`
		// resolve to different kinds of entry — the key's own secret.render row
		// and the KindRender account of the whole render — and asserting only
		// the token let the wrong sequence be threaded here without failing:
		// substituting the render root's seq for the key's kept the suite
		// green. So look up what the citation must point at and require it.
		key := keyEntryFor(t, st, "csrv", "DSN")
		want := fmt.Sprintf("(carried by #%d)", key.Seq)
		if !strings.Contains(e.Details, want) {
			t.Errorf("an input's entry does not cite the key entry that carried it — want %s, got %q", want, e.Details)
		}
		// And that it is not the render root, which is the substitution this
		// guards against and which reads identically at the prefix.
		if strings.Contains(e.Details, "(render #") {
			t.Errorf("an input's entry cites the render root, not the key entry: %q", e.Details)
		}
		return
	}
	t.Fatal("rendering a derived secret to disk left no trace on the input whose value it carries")
}

// keyEntryFor returns a secret's own per-key render entry — the direct
// disclosure, not the one written because something derives from it. That is
// what an input's `(carried by #N)` must resolve to.
func keyEntryFor(t *testing.T, st *store.Store, project, name string) store.AuditEntry {
	t.Helper()
	for _, e := range renderEntriesFor(t, st, project, name) {
		if strings.HasPrefix(e.Details, "plaintext written to ") {
			return e
		}
	}
	t.Fatalf("no per-key render entry for %s/%s", project, name)
	return store.AuditEntry{}
}

// renderEntriesFor returns the render disclosures recorded against a secret.
func renderEntriesFor(t *testing.T, st *store.Store, project, name string) []store.AuditEntry {
	t.Helper()
	sec, err := st.GetSecret(project, name)
	if err != nil {
		t.Fatal(err)
	}
	if sec == nil {
		t.Fatalf("no secret %s/%s", project, name)
	}
	entries, err := st.ListAudit(0, sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range entries {
		if e.Action == "secret.render" {
			out = append(out, e)
		}
	}
	return out
}

// hasRenderTargetEntry reports whether the render's own per-target entry — the
// one that predates SGNT-34 — is still being written.
func hasRenderTargetEntry(t *testing.T, st *store.Store) bool {
	t.Helper()
	entries, err := st.ListAudit(0, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == "render" && e.EventKind == store.KindRender && e.SecretID == "" {
			return true
		}
	}
	return false
}
