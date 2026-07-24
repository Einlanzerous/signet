package config

import "testing"

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
