// Package config loads signet's configuration from environment variables with
// sensible host-local defaults. Signet is a host-resident daemon, so defaults
// live under the invoking user's home directory, not in the docker stack.
package config

import (
	"net"
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
		GitHubToken:   envOr("SIGNET_GITHUB_TOKEN", envOr("SIGNET_PAT", "")),
		APIToken:      os.Getenv("SIGNET_API_TOKEN"),
		Addrs:         parseAddrs(envOr("SIGNET_ADDR", defaultAddr)),
	}
}

// parseAddrs splits a comma-separated SIGNET_ADDR, trimming each entry so
// `a, b` and `a,b` mean the same thing.
//
// An exact repeat is collapsed: that is a copy-paste stutter in a unit file,
// and it would otherwise fail the start with "address already in use" against
// an address that is in fact free. Entries that overlap without being
// identical — `:4010` and `0.0.0.0:4010` — are deliberately left as written
// and fail at bind, named: only the kernel knows those two collide, and
// guessing at it here would mean silently dropping an address someone asked
// for. Port 0 is never collapsed, because it means "any free port", so two
// such entries are two different listeners rather than a repeat.
//
// A value that yields nothing at all falls back to the default, which is what
// an empty SIGNET_ADDR already does.
func parseAddrs(raw string) []string {
	var addrs []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		addr := strings.TrimSpace(part)
		if addr == "" {
			continue
		}
		if !ephemeralPort(addr) {
			if seen[addr] {
				continue
			}
			seen[addr] = true
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return []string{defaultAddr}
	}
	return addrs
}

// ephemeralPort reports whether addr asks the kernel for whatever port is
// free. An address the daemon will reject outright is not this function's
// business — it answers false and lets the bind path say so.
func ephemeralPort(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	return err == nil && port == "0"
}

// envOr returns the environment's value for key, or def when it supplies none.
//
// A variable holding only whitespace supplies none. This is where that has to
// be decided, because this is where the fallback chain is: SIGNET_GITHUB_TOKEN
// collapses onto SIGNET_PAT here, so a whitespace-only value judged non-empty
// wins the collapse and discards a perfectly good SIGNET_PAT behind it. Trimming
// further down — at the point the token is used — is too late to help; by then
// the second variable has already been dropped.
//
// The value is returned trimmed, not merely tested that way: every consumer
// here is a path, an address, or a credential, and none of them wants the
// trailing \r a CRLF .env file leaves on the end.
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
