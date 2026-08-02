// Package config loads signet's configuration from environment variables with
// sensible host-local defaults. Signet is a host-resident daemon, so defaults
// live under the invoking user's home directory, not in the docker stack.
package config

import (
	"os"
	"path/filepath"
	"strings"
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
	// Addrs are the HTTP listen addresses (SIGNET_ADDR, comma-separated).
	//
	// A list rather than a single address because a host serving both
	// host-local and containerized clients would otherwise have to choose:
	// loopback strands every container, and 0.0.0.0 puts a credential vault on
	// every interface the host happens to have, including the LAN.
	Addrs []string
}

// defaultAddr is where the daemon listens when SIGNET_ADDR says nothing:
// loopback only, because a vault should not arrive on a new interface by
// default.
const defaultAddr = "127.0.0.1:4010"

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
		Addrs:         parseAddrs(envOr("SIGNET_ADDR", defaultAddr)),
	}
}

// parseAddrs splits a comma-separated SIGNET_ADDR, trimming each entry so
// `a, b` and `a,b` mean the same thing.
//
// Duplicates are collapsed rather than passed through: binding the same
// address twice can only be a typo, and it would otherwise fail the daemon's
// start with "address already in use" against an address that is in fact free —
// a confusing way to report a stutter in a config file.
//
// A value that yields nothing at all falls back to the default, which is what
// an empty SIGNET_ADDR already does.
func parseAddrs(raw string) []string {
	var addrs []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		addr := strings.TrimSpace(part)
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return []string{defaultAddr}
	}
	return addrs
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
