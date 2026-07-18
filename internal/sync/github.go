// Package sync reconciles vault secrets with their outbound targets.
//
// GitHub Actions repo secrets are push-only: workflows resolve ${{ secrets.* }}
// from GitHub's own store, so a local vault can never serve them at runtime —
// sealing with the repo public key and PUTting is the only mechanism. Drift
// detection is therefore metadata-based (GitHub never returns secret values):
// an out-of-band update or a missing secret counts as drift.
package sync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// ErrNotFound reports a 404 from the GitHub API (repo or secret absent).
var ErrNotFound = errors.New("not found")

// GHClient is a minimal GitHub REST client for Actions repo secrets.
type GHClient struct {
	BaseURL string // default https://api.github.com
	Token   string
	HTTP    *http.Client
}

// NewGHClient builds a client with defaults.
func NewGHClient(token string) *GHClient {
	return &GHClient{BaseURL: "https://api.github.com", Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// PublicKey is a repository's Actions secret sealing key.
type PublicKey struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"` // base64-encoded 32-byte curve25519 public key
}

// SecretMeta is the metadata GitHub exposes for an Actions secret. Values are
// never readable back.
type SecretMeta struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func (c *GHClient) do(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s %s: %w", method, path, ErrNotFound)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// RepoPublicKey fetches the sealing key for owner/name.
func (c *GHClient) RepoPublicKey(ctx context.Context, repo string) (PublicKey, error) {
	var pk PublicKey
	err := c.do(ctx, http.MethodGet, "/repos/"+repo+"/actions/secrets/public-key", nil, &pk)
	return pk, err
}

// PutSecret creates or updates an Actions repo secret with a sealed value.
func (c *GHClient) PutSecret(ctx context.Context, repo, name, sealedB64, keyID string) error {
	body, _ := json.Marshal(map[string]string{"encrypted_value": sealedB64, "key_id": keyID})
	return c.do(ctx, http.MethodPut, "/repos/"+repo+"/actions/secrets/"+name, body, nil)
}

// GetSecretMeta fetches an Actions secret's metadata (ErrNotFound if absent).
func (c *GHClient) GetSecretMeta(ctx context.Context, repo, name string) (SecretMeta, error) {
	var m SecretMeta
	err := c.do(ctx, http.MethodGet, "/repos/"+repo+"/actions/secrets/"+name, nil, &m)
	return m, err
}

// Seal encrypts plaintext to the repo public key with a libsodium-compatible
// anonymous sealed box and returns it base64-encoded.
func Seal(publicKeyB64 string, plaintext []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return "", fmt.Errorf("seal: bad public key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("seal: public key must be 32 bytes, got %d", len(raw))
	}
	var pk [32]byte
	copy(pk[:], raw)
	sealed, err := box.SealAnonymous(nil, plaintext, &pk, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// GHDrift classifies a gh-actions target's remote state.
type GHDrift string

const (
	// GHInSync means the destination reflects our last push.
	GHInSync GHDrift = "in sync"
	// GHMissing means the destination secret does not exist.
	GHMissing GHDrift = "missing"
	// GHOutOfBand means the destination changed after our last push.
	GHOutOfBand GHDrift = "drift"
)

// CheckGHDrift compares remote metadata against our last recorded push time.
func (c *GHClient) CheckGHDrift(ctx context.Context, repo, name, lastPushedAt string) (GHDrift, error) {
	meta, err := c.GetSecretMeta(ctx, repo, name)
	if errors.Is(err, ErrNotFound) {
		return GHMissing, nil
	}
	if err != nil {
		return "", err
	}
	if lastPushedAt == "" {
		return GHOutOfBand, nil // exists remotely but we never pushed it
	}
	pushed, err1 := time.Parse(time.RFC3339, lastPushedAt)
	updated, err2 := time.Parse(time.RFC3339, meta.UpdatedAt)
	if err1 != nil || err2 != nil {
		return GHInSync, nil // unparseable timestamps: assume ok rather than false-alarm
	}
	// Small tolerance: GitHub's updated_at is set momentarily after our PUT.
	if updated.After(pushed.Add(2 * time.Minute)) {
		return GHOutOfBand, nil
	}
	return GHInSync, nil
}
