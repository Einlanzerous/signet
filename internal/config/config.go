// Package config loads signet's configuration from environment variables with
// sensible host-local defaults. Signet is a host-resident daemon, so defaults
// live under the invoking user's home directory, not in the docker stack.
package config

import (
	"os"
	"path/filepath"
)

// Config is the resolved runtime configuration.
type Config struct {
	// DBPath is the SQLite database location (SIGNET_DB).
	DBPath string
	// MasterKeyFile holds the hex-encoded 32-byte AES key (SIGNET_MASTER_KEY_FILE).
	MasterKeyFile string
	// GitHubToken authenticates outbound GitHub Actions secret pushes
	// (SIGNET_GITHUB_TOKEN, or SIGNET_PAT as a fallback). Empty disables
	// gh-actions sync.
	GitHubToken string
	// APIToken is the bearer token required by the HTTP API (SIGNET_API_TOKEN).
	APIToken string
	// Addr is the HTTP listen address (SIGNET_ADDR).
	Addr string
}

// Load reads configuration from the environment, filling defaults.
func Load() Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return Config{
		DBPath:        envOr("SIGNET_DB", filepath.Join(home, ".local", "share", "signet", "signet.db")),
		MasterKeyFile: envOr("SIGNET_MASTER_KEY_FILE", filepath.Join(home, ".config", "signet", "master.key")),
		GitHubToken:   envOr("SIGNET_GITHUB_TOKEN", os.Getenv("SIGNET_PAT")),
		APIToken:      os.Getenv("SIGNET_API_TOKEN"),
		Addr:          envOr("SIGNET_ADDR", "127.0.0.1:4010"),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
