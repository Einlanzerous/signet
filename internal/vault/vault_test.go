package vault

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("s3cret-value with spaces & symbols #!/")
	nonce, ct, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := Decrypt(key, nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q != %q", got, plaintext)
	}
}

func TestTamperDetected(t *testing.T) {
	key, _ := GenerateKey()
	nonce, ct, err := Encrypt(key, []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xff
	if _, err := Decrypt(key, nonce, ct); err == nil {
		t.Fatal("tampered ciphertext decrypted without error")
	}
}

func TestWrongKeyFails(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	nonce, ct, _ := Encrypt(k1, []byte("value"))
	if _, err := Decrypt(k2, nonce, ct); err == nil {
		t.Fatal("wrong key decrypted without error")
	}
}

func TestKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "master.key")
	key, _ := GenerateKey()
	if err := WriteKeyFile(path, key); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(path, key); err == nil {
		t.Fatal("overwrite should be refused")
	}
	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, key) {
		t.Fatal("loaded key differs")
	}
}

func TestVersionHash(t *testing.T) {
	h := VersionHash([]byte("nonce"), []byte("ct"))
	if len(h) != 6 {
		t.Fatalf("want 6 hex chars, got %q", h)
	}
	if h == VersionHash([]byte("nonce"), []byte("ct2")) {
		t.Fatal("different ciphertexts hashed identically")
	}
}

func TestRandomToken(t *testing.T) {
	a, err := RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RandomToken(32)
	if len(a) != 32 || a == b {
		t.Fatalf("bad tokens: %q %q", a, b)
	}
}
