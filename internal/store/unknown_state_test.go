package store

import "testing"

// reload re-reads the project's single rendered target, so a state is judged
// from the row the database actually holds rather than from a struct the test
// filled in. That distinction is the whole point here: the bug lived in how an
// empty last_pushed_digest COLUMN reaches GHState, and a hand-built Target that
// happens to leave the field zero is not evidence about the column.
func reload(t *testing.T, s *Store, project string) *Target {
	t.Helper()
	targets, err := s.RenderTargetsForProject(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("project %s has %d rendered targets, want 1", project, len(targets))
	}
	return &targets[0]
}

// A delivery that recorded neither fingerprint nor version has nothing to
// compare against. `unknown` is the state for exactly that, and until SGNT-43
// it could not be reached: GHState compared the digest before testing whether
// there was one, so the empty column made `"" != digest` trivially true and
// such a target reported `drift`.
//
// `drift` is a definite claim — renderedTargetNote words it "now stale" and
// suggests a sync — about a destination whose currency is unrecorded. It is the
// same unchecked claim `unknown` exists to avoid, pointing the other way.
//
// NO RELEASE WRITES THIS ROW. Every success path fills one of the two columns
// and every prov == nil path leaves last_pushed_at empty — GHState's own doc
// enumerates the writers. The row is built here through the store API to pin
// what the function answers if a future push path ever leaves both unwritten,
// which is the whole reason the branch is kept. Read it as a guard, not as a
// regression test for something observed.
func TestADeliveryWithNothingRecordedToCompareIsUnknownNotDrift(t *testing.T) {
	s := testStore(t)
	tgt := mustAddRenderTarget(t, s, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"ALPHA"})

	// prov == nil sets last_pushed_at and leaves both fingerprint columns
	// untouched. In production that pairing does not occur — nil provenance is
	// the failure/refusal call and always carries an empty timestamp — so this
	// is the store API being used to construct a shape, not to replay one.
	if err := s.UpdateTargetPush(tgt.ID, "in sync", "", nil, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	got := reload(t, s, "csrv").GHState(nil, "d0d0d0d0d0d0")
	if got == "drift" {
		t.Fatalf("a delivery with no recorded fingerprint reports %q — a definite claim that "+
			"the destination is stale, made by comparing against a column nobody wrote", got)
	}
	if got != "unknown" {
		t.Fatalf("got %q, want unknown", got)
	}
}

// The other half of the reorder: moving the emptiness test in front of the
// comparison must not stop the comparison working. A target that DOES carry a
// fingerprint still answers on it, in both directions.
func TestARecordedFingerprintIsStillCompared(t *testing.T) {
	s := testStore(t)
	tgt := mustAddRenderTarget(t, s, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"ALPHA"})

	const delivered = "d0d0d0d0d0d0"
	if err := s.UpdateTargetPush(tgt.ID, "in sync", "", &PushProvenance{Digest: delivered}, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	if got := reload(t, s, "csrv").GHState(nil, delivered); got != "in sync" {
		t.Errorf("an unchanged blob reports %q, want in sync", got)
	}
	if got := reload(t, s, "csrv").GHState(nil, "ffffffffffff"); got != "drift" {
		t.Errorf("a changed blob reports %q, want drift", got)
	}
}

// The combination the CLI half of SGNT-43 turns on, and the reason `unknown`'s
// exclusion from the reason mark had to be re-decided rather than inherited.
//
// `refuse` passes prov == nil, so a refusal leaves the fingerprint columns
// exactly as they were. A target in the state above that is then refused keeps
// both columns empty AND carries a live refusal — it lands in `unknown`, where
// the state word says only that signet cannot tell whether the destination is
// current, so everything an operator could act on is in LastError.
//
// Same caveat as above: the base row is constructed, not replayed. What this
// pins is that the refusal genuinely does leave the columns alone, which is the
// half of the argument that is about production code rather than about a shape.
func TestARefusalOnARecordlessDeliveryLandsInUnknown(t *testing.T) {
	s := testStore(t)
	tgt := mustAddRenderTarget(t, s, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"ALPHA"})

	if err := s.UpdateTargetPush(tgt.ID, "in sync", "", nil, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	const refusal = "this render drops 1 key(s) the last push delivered: BETA"
	if err := s.UpdateTargetPush(tgt.ID, TargetRefused, refusal, nil, ""); err != nil {
		t.Fatal(err)
	}

	got := reload(t, s, "csrv")
	if got.LastPushedDigest != "" {
		t.Fatalf("the refusal wrote a fingerprint (%q) — this case depends on it not doing so",
			got.LastPushedDigest)
	}
	if state := got.GHState(nil, "d0d0d0d0d0d0"); state != "unknown" {
		t.Fatalf("a refusal on a delivery with nothing recorded reports %q, want unknown", state)
	}
	if got.LastError != refusal {
		t.Errorf("the refusal's reason is not on the row: %q", got.LastError)
	}
}

// The distinction the reorder must NOT flatten (found by the reviewer on #46).
//
// An empty digest reaches this branch from two shapes, and only one of them is
// an absence of evidence. A delivery of a STORED version records a version id
// and no digest; if that secret is derived now, the destination holds a value
// the vault has replaced — provable drift. A row recording NEITHER is the case
// `unknown` is for, and the one production does not write.
//
// This is the half that matters in practice, because the stored-then-converted
// shape is the one a real vault can hold.
func TestAVersionIDDistinguishesASupersededDeliveryFromAnUnknownOne(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "proj", "DSN", "", false)
	tgt := mustAddGHTarget(t, s, sec.ID, "owner/repo", "DSN")

	// A stored secret's push: version id, no digest — exactly what PushSecret
	// writes when resolve.Current returns a Version and an empty Digest.
	if err := s.UpdateTargetPush(tgt.ID, "in sync", "",
		&PushProvenance{VersionID: "vid1"}, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	targets, err := s.TargetsForSecret(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The secret is derived now, so the caller supplies a digest. The row still
	// says what was delivered.
	if got := targets[0].GHState(nil, "d0d0d0d0d0d0"); got != "drift" {
		t.Errorf("a destination holding a superseded stored version reports %q, want drift", got)
	}

	// A row recording NEITHER stays unknown — the defensive case. Built through
	// the store rather than by zeroing the field on the struct above, because
	// this file's own preamble says a hand-built Target is not evidence about a
	// column (found by the review on #46, which noticed the last test in the
	// file broke the rule the first three keep).
	other := mustCreateSecret(t, s, "proj", "OTHER", "", false)
	otherTgt := mustAddGHTarget(t, s, other.ID, "owner/repo", "OTHER")
	if err := s.UpdateTargetPush(otherTgt.ID, "in sync", "", nil, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	blank, err := s.TargetsForSecret(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := blank[0].GHState(nil, "d0d0d0d0d0d0"); got != "unknown" {
		t.Errorf("a delivery with neither a version nor a fingerprint reports %q, want unknown", got)
	}
}

// The mirror of the narrowing, and the reason the version-id branch carries no
// emptiness guard of its own.
//
// A push of a DERIVED value clears last_pushed_version_id, because the
// provenance branch writes
//
//	last_pushed_version_id = NULLIF(?, '')
//
// and a derived push supplies the empty string for it. So after a
// `derive --clear` turns that secret back into a stored one, the version-id
// branch sees an empty column. That is not an absence of evidence: the
// destination holds a composed blob and the vault holds a stored version, so
// the vault has provably moved on.
//
// The SQL is an indented code block on purpose. In a DOC comment gofmt
// rewrites two ASCII apostrophes to a typographic U+201D — which is not valid
// SQLite, and cannot be grepped against the line it quotes, in a comment whose
// whole point is that the claim should be audited rather than trusted. (This
// sentence itself was rewritten that way on the first attempt.) A code block is
// left verbatim; so is an inline comment inside a function body, which is why
// targets.go can write it on one line.
//
// Guarding it as `unknown` — the symmetrical-looking change — would report
// "signet cannot tell" about a difference the row proves, which is the same
// mistake the digest branch's first draft made in the other direction.
func TestAClearedDerivationStillReportsDrift(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "p", "DSN", "", false)
	tgt := mustAddGHTarget(t, s, sec.ID, "o/r", "DSN")

	// The derived push: a digest recorded, and the version id cleared with it.
	if err := s.UpdateTargetPush(tgt.ID, "in sync", "",
		&PushProvenance{Digest: "d0d0d0d0d0d0"}, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	targets, err := s.TargetsForSecret(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if targets[0].LastPushedVersionID != "" {
		t.Fatalf("a derived push left a version id (%q) — this case depends on it clearing one",
			targets[0].LastPushedVersionID)
	}

	// `derive --clear` has since restored a stored value, so the caller now
	// supplies a version and no digest.
	if got := targets[0].GHState(&Version{ID: "vid-current"}, ""); got != "drift" {
		t.Errorf("a destination holding a composed blob the vault has replaced reports %q, want drift", got)
	}
}
