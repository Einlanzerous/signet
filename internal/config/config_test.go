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
