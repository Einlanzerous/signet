package config

import (
	"slices"
	"testing"
)

func TestAddrResolution(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want []string
	}{
		{name: "unset falls back to loopback", env: "", want: []string{defaultAddr}},
		{name: "single address unchanged", env: "127.0.0.1:4010", want: []string{"127.0.0.1:4010"}},
		{name: "loopback plus docker bridge", env: "127.0.0.1:4010,172.17.0.1:4010",
			want: []string{"127.0.0.1:4010", "172.17.0.1:4010"}},
		{name: "whitespace around entries", env: " 127.0.0.1:4010 , 172.17.0.1:4010 ",
			want: []string{"127.0.0.1:4010", "172.17.0.1:4010"}},
		{name: "empty entries dropped", env: "127.0.0.1:4010,,", want: []string{"127.0.0.1:4010"}},
		// A stutter in a unit file must not fail the start with "address already
		// in use" against an address that is free.
		{name: "duplicates collapsed", env: "127.0.0.1:4010,127.0.0.1:4010", want: []string{"127.0.0.1:4010"}},
		{name: "order preserved", env: "172.17.0.1:4010,127.0.0.1:4010",
			want: []string{"172.17.0.1:4010", "127.0.0.1:4010"}},
		{name: "nothing but separators", env: " , ", want: []string{defaultAddr}},
		// Port 0 is "any free port", so two such entries are two listeners.
		// Collapsing them would silently serve one address fewer than asked.
		{name: "ephemeral ports not collapsed", env: "127.0.0.1:0,127.0.0.1:0",
			want: []string{"127.0.0.1:0", "127.0.0.1:0"}},
		// Overlapping-but-distinct spellings are left alone: only the kernel
		// knows they collide, and it reports it by name at bind time.
		{name: "overlapping spellings preserved", env: ":4010,0.0.0.0:4010",
			want: []string{":4010", "0.0.0.0:4010"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SIGNET_ADDR", tt.env)
			if got := Load().Addrs; !slices.Equal(got, tt.want) {
				t.Errorf("Addrs = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGitHubTokenResolution(t *testing.T) {
	tests := []struct {
		name      string
		ghToken   string
		pat       string
		wantToken string
	}{
		{name: "canonical only", ghToken: "gh-tok", pat: "", wantToken: "gh-tok"},
		{name: "pat fallback", ghToken: "", pat: "pat-tok", wantToken: "pat-tok"},
		{name: "canonical wins over pat", ghToken: "gh-tok", pat: "pat-tok", wantToken: "gh-tok"},
		{name: "neither set", ghToken: "", pat: "", wantToken: ""},
		// A variable holding only whitespace supplies no credential, so it must
		// not win the collapse. Judging it non-empty here discards the SIGNET_PAT
		// behind it — and no amount of trimming further down can get it back,
		// because by then the second variable has already been dropped.
		{name: "blank canonical yields to pat", ghToken: "   ", pat: "pat-tok", wantToken: "pat-tok"},
		{name: "crlf canonical yields to pat", ghToken: "\r\n", pat: "pat-tok", wantToken: "pat-tok"},
		{name: "both blank resolve to nothing", ghToken: " ", pat: "\t", wantToken: ""},
		// Values that do carry a credential arrive usable: this one goes
		// straight into an Authorization header.
		{name: "surrounding whitespace trimmed", ghToken: " gh-tok\r\n", pat: "", wantToken: "gh-tok"},
		{name: "pat fallback trimmed", ghToken: "", pat: "\tpat-tok\n", wantToken: "pat-tok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SIGNET_GITHUB_TOKEN", tt.ghToken)
			t.Setenv("SIGNET_PAT", tt.pat)
			if got := Load().GitHubToken; got != tt.wantToken {
				t.Errorf("GitHubToken = %q, want %q", got, tt.wantToken)
			}
		})
	}
}
