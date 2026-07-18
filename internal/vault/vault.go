// Package vault implements signet's at-rest crypto: AES-256-GCM with a
// 32-byte master key kept hex-encoded in a mode-0400 file on the host.
//
// The version hash shown throughout the UI ("#a3f9c1") is derived from the
// nonce and ciphertext only — never from the plaintext alone — so it cannot be
// used to confirm guesses of low-entropy secret values offline.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

// NonceSize is the GCM nonce length in bytes.
const NonceSize = 12

// GenerateKey returns a fresh random 32-byte master key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	return key, nil
}

// WriteKeyFile writes the key hex-encoded to path with mode 0400, creating
// parent directories (0700). It refuses to overwrite an existing file.
func WriteKeyFile(path string, key []byte) error {
	if len(key) != KeySize {
		return fmt.Errorf("write key file: key must be %d bytes, got %d", KeySize, len(key))
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("write key file: %s already exists (refusing to overwrite)", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o400); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

// LoadKey reads and decodes the hex-encoded master key from path.
func LoadKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load master key: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("load master key %s: not valid hex: %w", path, err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("load master key %s: want %d bytes, got %d", path, KeySize, len(key))
	}
	return key, nil
}

// Encrypt seals plaintext under key, returning a fresh random nonce and the
// ciphertext (which includes the GCM auth tag).
func Encrypt(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("encrypt: %w", err)
	}
	return nonce, aead.Seal(nil, nonce, plaintext, nil), nil
}

// Decrypt opens ciphertext produced by Encrypt.
func Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("aead: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	return cipher.NewGCM(block)
}

// VersionHash returns the short display hash for a stored version:
// the first 6 hex chars of SHA-256(nonce || ciphertext).
func VersionHash(nonce, ciphertext []byte) string {
	sum := sha256.Sum256(append(append([]byte{}, nonce...), ciphertext...))
	return hex.EncodeToString(sum[:])[:6]
}

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// RandomToken returns an n-character alphanumeric secret value, used for
// --generate secrets and rotation of generated secrets.
func RandomToken(n int) (string, error) {
	out := make([]byte, n)
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	for i, b := range buf {
		out[i] = tokenAlphabet[int(b)%len(tokenAlphabet)]
	}
	return string(out), nil
}
