// Package version holds the build version string, overridable at link time:
//
//	go build -ldflags "-X github.com/Einlanzerous/signet/internal/version.Version=v1.2.3"
package version

// Version is the signet build version.
var Version = "0.1.0-dev"
