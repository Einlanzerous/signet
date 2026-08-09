// Package logtest captures what a test wrote to the standard logger.
//
// It exists because the operator-facing behaviour worth asserting on in this
// project is often a log line rather than a return value — a daemon that stops
// without saying so is the bug SGNT-19 is about, and a test can only hold that
// line in place by reading it back. Two packages need that, so it lives here
// rather than being copied into each with the copies drifting.
package logtest

import (
	"bytes"
	"log"
	"sync"
	"testing"
)

// Capture redirects the standard logger for the duration of one test and
// returns a func reporting everything written to it. The previous writer is
// restored on cleanup, so a failure here cannot silence the rest of the
// package.
//
// Tests using it must not run in parallel with each other: the logger they
// capture is process-wide.
func Capture(t testing.TB) func() string {
	t.Helper()
	buf := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf.String
}

// syncBuffer guards a bytes.Buffer, because the line under test is typically
// written by the goroutine under test and read by the test's own. Its zero
// value is usable.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
