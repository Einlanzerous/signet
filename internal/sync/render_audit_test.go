package sync

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/Einlanzerous/signet/internal/store"
)

// A rendered target delivers many secrets' plaintext as one blob, and recorded
// only the TargetID — a blob composed from many secrets has no single one to
// name, so the entry named none of them. Checking whether `sync` shared
// `render`'s gap (SGNT-34) found this, and it is the larger exposure of the
// two: the construct-server render carries 95 keys, every one of them invisible
// from its own ledger.
func TestPushRenderIsAuditedPerSecret(t *testing.T) {
	gh, _, _, _ := renderServer(t)
	values := map[string]string{"ALPHA": "a", "BETA": "b"}
	st, key, target := renderFixture(t, gh.BaseURL, []string{"ALPHA", "BETA"}, values)

	res, err := PushRender(context.Background(), st, key, gh, target, values, RenderPushOptions{}, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "in sync" {
		t.Fatalf("push did not succeed: %+v", res)
	}
	if res.AuditErr != "" {
		t.Fatalf("ledger write failed: %s", res.AuditErr)
	}

	// Both keys, not just the first: a loop that recorded one and stopped would
	// answer this query correctly for exactly one credential.
	for _, name := range []string{"ALPHA", "BETA"} {
		entries := pushEntriesFor(t, st, "csrv", name)
		if len(entries) == 0 {
			t.Errorf("%s's plaintext was delivered in the blob and left no entry on that secret", name)
			continue
		}
		if !strings.Contains(entries[0].Details, "o/r") {
			t.Errorf("%s's entry does not name the destination: %q", name, entries[0].Details)
		}
		if !strings.Contains(entries[0].Details, "#") {
			t.Errorf("%s's entry cites no digest, so two pushes are indistinguishable: %q", name, entries[0].Details)
		}
	}

	// The per-target entry stays. It is the record of the push — the key count,
	// the scope, the digest — and something audits renders by target.
	entries, err := st.ListAudit(50, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == "sync.push" && e.SecretID == "" && strings.Contains(e.Details, "render") {
			return
		}
	}
	t.Error("the per-target render push entry is gone; the per-secret entries are a second index, not a replacement")
}

// A derived secret's value carries its inputs', so pushing it sends theirs —
// off-box, to a destination nothing can read back. PushSecret's entry names the
// derived secret alone, which is the gap SGNT-18 closed for `reveal` surviving
// in the channel that leaves the machine.
func TestPushAuditsTheInputsOfADerivedSecret(t *testing.T) {
	gh := repoPushServer(t)
	st, key, _ := renderFixture(t, gh.BaseURL, []string{"ALPHA"}, map[string]string{"ALPHA": "a"})

	// A derived secret over ALPHA, with a destination of its own. Composed
	// without spelling a connection string: what is under test is that the
	// input is audited, not the shape of the value that carries it.
	dsn, _, err := store.MutateValue(st, func(m *store.Mutation) (*store.Secret, store.AuditRecord, error) {
		s, err := m.CreateSecret("csrv", "DSN", "", false, "")
		if err != nil {
			return nil, store.AuditRecord{}, err
		}
		if err := m.SetDerivation(s.ID, "wrapper[{{csrv/ALPHA}}]wrapper"); err != nil {
			return nil, store.AuditRecord{}, err
		}
		if _, err := m.AddGHTarget(s.ID, "o/r", "", "DSN"); err != nil {
			return nil, store.AuditRecord{}, err
		}
		s.Derivation = "wrapper[{{csrv/ALPHA}}]wrapper"
		return s, store.AuditRecord{
			Actor: "test", Action: "secret.derive", SecretID: s.ID, Details: "fixture",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	results, err := PushSecret(context.Background(), st, key, gh, dsn, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].State != "in sync" {
		t.Fatalf("push did not succeed: %+v", results)
	}

	for _, e := range pushEntriesFor(t, st, "csrv", "ALPHA") {
		if !strings.Contains(e.Details, "derives from it") {
			continue
		}
		// An input's entry has to distinguish one delivery from the next, or a
		// secret pushed on every deploy returns N identical rows. The direct
		// entry cites its provenance; so does this one.
		if !strings.Contains(e.Details, "#") {
			t.Errorf("an input's entry cites no provenance, so two pushes are indistinguishable: %q", e.Details)
		}
		return
	}
	t.Fatal("pushing a derived secret to GitHub left no trace on the input whose value it carries")
}

// repoPushServer answers a successful repository-scope push of o/r · DSN.
func repoPushServer(t *testing.T) *GHClient {
	t.Helper()
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/actions/secrets/public-key", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(PublicKey{KeyID: "k", Key: base64.StdEncoding.EncodeToString(pub[:])})
	})
	mux.HandleFunc("PUT /repos/o/r/actions/secrets/DSN", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /repos/o/r/actions/secrets/DSN", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(SecretMeta{Name: "DSN", UpdatedAt: "2026-07-01T12:00:00Z"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewGHClient("tok")
	c.BaseURL = srv.URL
	return c
}

// pushEntriesFor returns the push disclosures recorded against a secret.
func pushEntriesFor(t *testing.T, st *store.Store, project, name string) []store.AuditEntry {
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
		if e.Action == "sync.push" {
			out = append(out, e)
		}
	}
	return out
}

// The rendered blob can carry a DERIVED key, in which case the push discloses
// that key's inputs too — and their entries need the same digest the direct
// ones carry, or a target pushed on every deploy writes rows against its inputs
// that cannot be told apart. Round 1 of the review on #43 found this asymmetry
// on the CLI render path; it was fixed there and left here.
func TestPushRenderAuditsDerivedInputsWithTheDigest(t *testing.T) {
	gh, _, _, _ := renderServer(t)
	st, key, _ := renderFixture(t, gh.BaseURL, []string{"ALPHA", "DSN"}, map[string]string{"ALPHA": "a"})

	// DSN derives from ALPHA and is carried by the render target.
	if _, _, err := store.MutateValue(st, func(m *store.Mutation) (*store.Secret, store.AuditRecord, error) {
		sec, err := m.CreateSecret("csrv", "DSN", "", false, "")
		if err != nil {
			return nil, store.AuditRecord{}, err
		}
		if err := m.SetDerivation(sec.ID, "wrapper[{{csrv/ALPHA}}]wrapper"); err != nil {
			return nil, store.AuditRecord{}, err
		}
		return sec, store.AuditRecord{
			Actor: "test", Action: "secret.derive", SecretID: sec.ID, Details: "fixture",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
		}, nil
	}); err != nil {
		t.Fatal(err)
	}

	targets, err := st.RenderTargetsForProject("csrv")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"ALPHA": "a", "DSN": "wrapper[a]wrapper"}
	res, err := PushRender(context.Background(), st, key, gh, &targets[0], want, RenderPushOptions{}, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "in sync" || res.AuditErr != "" {
		t.Fatalf("push did not succeed cleanly: %+v", res)
	}

	for _, e := range pushEntriesFor(t, st, "csrv", "ALPHA") {
		if !strings.Contains(e.Details, "derives from it") {
			continue
		}
		if !strings.Contains(e.Details, "#") {
			t.Errorf("the input's entry cites no digest, so two pushes are indistinguishable: %q", e.Details)
		}
		return
	}
	t.Fatal("a render carrying a derived key left no trace on the input whose value it carries")
}
