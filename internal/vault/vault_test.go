package vault

import (
	"bytes"
	"encoding/hex"
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

func TestKeyedSaltIsAPureFunctionOfKeyAndContext(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	a := KeyedSalt(key, 16, "scrypt", "p/A", "hunter2")
	if len(a) != 16 {
		t.Fatalf("got %d bytes, want 16", len(a))
	}
	if !bytes.Equal(a, KeyedSalt(key, 16, "scrypt", "p/A", "hunter2")) {
		t.Error("the same key and context gave two different salts")
	}
	if bytes.Equal(a, KeyedSalt(key, 16, "scrypt", "p/A", "hunter3")) {
		t.Error("a different context gave the same salt")
	}
	other := append([]byte{}, key...)
	other[0] ^= 1
	if bytes.Equal(a, KeyedSalt(other, 16, "scrypt", "p/A", "hunter2")) {
		t.Error("a different key gave the same salt — it is precomputable without the vault")
	}
	// A shorter salt is a prefix of the longer: n only truncates.
	if !bytes.Equal(a[:8], KeyedSalt(key, 8, "scrypt", "p/A", "hunter2")) {
		t.Error("KeyedSalt(n=8) is not the prefix of KeyedSalt(n=16)")
	}
}

// Without length prefixes ("ab","c") and ("a","bc") concatenate to the same
// bytes, and a value could be chosen to collide with another secret's context.
func TestKeyedSaltContextIsFramed(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	if bytes.Equal(KeyedSalt(key, 16, "ab", "c"), KeyedSalt(key, 16, "a", "bc")) {
		t.Error("two different contexts with the same concatenation share a salt")
	}
	if bytes.Equal(KeyedSalt(key, 16, "a", ""), KeyedSalt(key, 16, "a")) {
		t.Error("a trailing empty part is indistinguishable from none")
	}
}

// The salt is published inside every hash built on it, so it must not be the
// same construction as ValueDigest, whose truncated outputs are published too.
func TestKeyedSaltIsNotAValueDigest(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	salt := hex.EncodeToString(KeyedSalt(key, 6, "hunter2"))
	if salt == ValueDigest(key, "hunter2") {
		t.Error("a salt over a value equals the value's published digest")
	}
}

func TestKeyedSaltRejectsALengthItCannotFill(t *testing.T) {
	for _, n := range []int{0, -1, 33} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("KeyedSalt(n=%d) did not panic", n)
				}
			}()
			KeyedSalt(bytes.Repeat([]byte{7}, KeySize), n, "x")
		}()
	}
}
