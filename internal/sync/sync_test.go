package sync

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestSealOpensWithKeypair(t *testing.T) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealedB64, err := Seal(base64.StdEncoding.EncodeToString(pub[:]), []byte("the-secret"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		t.Fatal(err)
	}
	opened, ok := box.OpenAnonymous(nil, sealed, pub, priv)
	if !ok {
		t.Fatal("sealed box did not open")
	}
	if string(opened) != "the-secret" {
		t.Fatalf("opened %q", opened)
	}
}

func TestSealRejectsBadKey(t *testing.T) {
	if _, err := Seal("not-base64!!!", []byte("x")); err == nil {
		t.Fatal("bad base64 accepted")
	}
	if _, err := Seal(base64.StdEncoding.EncodeToString([]byte("short")), []byte("x")); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestGHClientPushAndDrift(t *testing.T) {
	pub, _, _ := box.GenerateKey(rand.Reader)
	var gotPut struct {
		EncryptedValue string `json:"encrypted_value"`
		KeyID          string `json:"key_id"`
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/actions/secrets/public-key", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(PublicKey{KeyID: "key1", Key: base64.StdEncoding.EncodeToString(pub[:])})
	})
	mux.HandleFunc("PUT /repos/o/r/actions/secrets/MY_SECRET", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotPut)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /repos/o/r/actions/secrets/MY_SECRET", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(SecretMeta{Name: "MY_SECRET", UpdatedAt: "2026-07-01T12:00:00Z"})
	})
	mux.HandleFunc("GET /repos/o/r/actions/secrets/ABSENT", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewGHClient("tok")
	c.BaseURL = srv.URL
	ctx := context.Background()

	pk, err := c.RepoPublicKey(ctx, "o/r")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(pk.Key, []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PutSecret(ctx, "o/r", "MY_SECRET", sealed, pk.KeyID); err != nil {
		t.Fatal(err)
	}
	if gotPut.KeyID != "key1" || gotPut.EncryptedValue == "" {
		t.Fatalf("PUT body wrong: %+v", gotPut)
	}

	// Drift: pushed after remote update → in sync.
	d, err := c.CheckGHDrift(ctx, "o/r", "MY_SECRET", "2026-07-01T12:00:30Z")
	if err != nil {
		t.Fatal(err)
	}
	if d != GHInSync {
		t.Fatalf("want in sync, got %q", d)
	}
	// Drift: remote updated well after our push → out of band.
	d, _ = c.CheckGHDrift(ctx, "o/r", "MY_SECRET", "2026-06-01T00:00:00Z")
	if d != GHOutOfBand {
		t.Fatalf("want drift, got %q", d)
	}
	// Missing secret.
	d, err = c.CheckGHDrift(ctx, "o/r", "ABSENT", "2026-06-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if d != GHMissing {
		t.Fatalf("want missing, got %q", d)
	}
}

func TestCheckFileDrift(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte("A=1\nB=wrong\nEXTRA=x\n"), 0o600)

	want := map[string]string{"A": "1", "B": "2", "C": "3"}
	d := CheckFile(path, want, []string{"A", "B", "C"})
	if d.MissingFile {
		t.Fatal("file exists")
	}
	states := map[string]string{}
	for _, k := range d.Keys {
		states[k.Key] = k.State
	}
	if states["A"] != "ok" || states["B"] != "changed" || states["C"] != "missing" {
		t.Fatalf("states wrong: %v", states)
	}
	if len(d.Unmanaged) != 1 || d.Unmanaged[0] != "EXTRA" {
		t.Fatalf("unmanaged wrong: %v", d.Unmanaged)
	}
	if d.Clean() {
		t.Fatal("drifted file reported clean")
	}

	missing := CheckFile(filepath.Join(dir, "nope"), want, []string{"A"})
	if !missing.MissingFile || missing.Clean() {
		t.Fatal("missing file not reported")
	}
}
