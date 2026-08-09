package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Einlanzerous/signet/internal/logtest"
)

// The daemon's two unexplained multi-day outages (SGNT-19) were only reachable
// through a cancelled serve context, and the context said nothing about what
// cancelled it. These tests hold the line that a signal now names itself, so a
// third occurrence arrives already diagnosed instead of needing a fourth.

func TestSignalContextNamesTheSignal(t *testing.T) {
	logged := logtest.Capture(t)

	ctx, stop := signalContext(syscall.SIGTERM)
	defer stop()

	// Safe to signal ourselves: Notify is registered by the time signalContext
	// returns, which suppresses the default terminate action.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("raising SIGTERM: %v", err)
	}

	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("SIGTERM did not cancel the serve context")
	}

	// The line is written before cancel, so observing Done means it is written.
	out := logged()
	if !strings.Contains(out, "SIGTERM") {
		t.Errorf("shutdown did not name the signal that caused it; log was %q", out)
	}
	if !strings.Contains(out, "shutting down") {
		t.Errorf("shutdown line does not say what it is doing; log was %q", out)
	}
}

// stop has to deregister the handler, not merely cancel the context. A serve
// that left Notify installed would leave the process silently swallowing every
// later SIGTERM — a worse failure than the one this ticket is about.
func TestSignalContextStopReleasesTheHandler(t *testing.T) {
	ctx, stop := signalContext(syscall.SIGTERM)
	stop()

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not cancel the serve context")
	}

	// Re-register, raise, and confirm the signal still reaches a fresh context:
	// if the first handler were still installed it could consume the signal.
	ctx2, stop2 := signalContext(syscall.SIGTERM)
	defer stop2()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("raising SIGTERM: %v", err)
	}
	select {
	case <-ctx2.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("SIGTERM was swallowed after a previous signalContext was stopped")
	}
}

func TestSignalNameFallsBackToTheSignalsOwnString(t *testing.T) {
	if got := signalName(syscall.SIGTERM); got != "SIGTERM" {
		t.Errorf("SIGTERM: got %q", got)
	}
	if got := signalName(os.Interrupt); got != "SIGINT" {
		t.Errorf("SIGINT: got %q", got)
	}
	// Anything unregistered still has to print as something legible rather
	// than being dropped on the floor.
	if got := signalName(syscall.SIGHUP); got == "" {
		t.Error("SIGHUP: got an empty name")
	}
}
