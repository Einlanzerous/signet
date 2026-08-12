package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Einlanzerous/signet/internal/logtest"
)

// listenLoopback returns bound listeners on n ephemeral loopback ports, and
// their addresses. Tests bind first and read the port back rather than guessing
// a free one, so nothing races another test for a fixed number.
func listenLoopback(t *testing.T, n int) ([]net.Listener, []string) {
	t.Helper()
	var listeners []net.Listener
	var addrs []string
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, ln)
		addrs = append(addrs, ln.Addr().String())
	}
	return listeners, addrs
}

func healthz(t *testing.T, addr string) int {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/healthz", addr))
	if err != nil {
		t.Fatalf("GET %s: %v", addr, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// Every configured address serves the same API — that is the whole point of the
// list: the container on the bridge and the CLI on loopback reach one daemon.
func TestServeBindsEveryAddress(t *testing.T) {
	srv, _, _, _ := testServer(t)
	listeners, addrs := listenLoopback(t, 3)
	for _, ln := range listeners {
		ln.Close() // hand the ports back; Serve binds them itself
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancelled on every exit, not only the happy one: without this a t.Fatalf
	// below leaves Serve running, holding three ports for the rest of the binary.
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, addrs, srv) }()
	waitReady(t, addrs)

	for _, addr := range addrs {
		if code := healthz(t, addr); code != http.StatusOK {
			t.Errorf("%s /healthz = %d, want 200", addr, code)
		}
	}

	// Graceful shutdown still ends the call, and ends it for every listener.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
	for _, addr := range addrs {
		if reachable(addr) {
			t.Errorf("%s still accepting after shutdown", addr)
		}
	}
}

// A daemon half-listening is the failure this ticket exists to prevent: healthy
// on /healthz from the host, refused from every container.
func TestServeFailsIfAnyAddressIsTaken(t *testing.T) {
	srv, _, _, _ := testServer(t)
	// One port held by someone else, one free.
	held, heldAddrs := listenLoopback(t, 1)
	defer held[0].Close()
	free, freeAddrs := listenLoopback(t, 1)
	free[0].Close()

	err := Serve(context.Background(), []string{freeAddrs[0], heldAddrs[0]}, srv)
	if err == nil {
		t.Fatal("Serve started with an unbindable address")
	}
	// The message has to name the address that failed; "bind: address already in
	// use" alone sends an operator to read the whole unit file.
	if !strings.Contains(err.Error(), heldAddrs[0]) {
		t.Errorf("error does not name the failing address: %v", err)
	}
	// And the one that did bind must have been handed back, not left held by a
	// daemon that never started.
	if reachable(freeAddrs[0]) {
		t.Errorf("%s left bound after a failed start", freeAddrs[0])
	}
}

func TestServeRejectsEmptyAddressList(t *testing.T) {
	srv, _, _, _ := testServer(t)
	err := Serve(context.Background(), nil, srv)
	if err == nil || !strings.Contains(err.Error(), "SIGNET_ADDR") {
		t.Fatalf("want an error naming SIGNET_ADDR, got %v", err)
	}
}

// Addresses that would bind something other than what they appear to say are
// refused before any port is taken — both of these would otherwise defeat the
// all-or-nothing guarantee while looking like a clean start.
func TestServeRejectsAddressesThatDefeatTheGuarantee(t *testing.T) {
	// A known-good address to pair each bad one with. The port is handed back
	// immediately — the test needs the address, not the listener.
	held, free := listenLoopback(t, 1)
	held[0].Close()
	cases := []struct {
		name string
		addr string
		want string
	}{
		// Resolves to 127.0.0.1 and ::1 but binds exactly one of them.
		{name: "hostname", addr: "localhost:4010", want: "IP literal"},
		// net.Listen("tcp", "") binds the wildcard — the whole-LAN exposure.
		{name: "empty entry", addr: "", want: "missing port"},
		{name: "no port", addr: "127.0.0.1", want: "missing port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _, _ := testServer(t)
			err := Serve(context.Background(), []string{free[0], tc.addr}, srv)
			if err == nil {
				t.Fatalf("Serve accepted %q", tc.addr)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not explain %q", err, tc.want)
			}
			// Rejected before anything was bound, so the valid address in the
			// same list was never taken.
			if reachable(free[0]) {
				t.Errorf("%s was bound despite a bad entry later in the list", free[0])
			}
		})
	}
}

// awaitStopped waits for a result that has not arrived yet rather than
// concluding from its absence — whatever ended that listener.
//
// It does not decide the coinciding case, and an earlier version of this
// comment said it did. Once Shutdown begins, http.Server hands Serve
// ErrServerClosed in place of the accept error, so a loss racing a signal
// arrives already relabelled and this function filters it as ordinary. See
// awaitStopped's own doc comment for what is and is not guaranteed.
func TestAwaitStopped(t *testing.T) {
	// An ordinary shutdown is not a failure, however many listeners report it.
	ch := make(chan error, 3)
	ch <- http.ErrServerClosed
	ch <- nil
	ch <- http.ErrServerClosed
	if got := awaitStopped(ch, 3); got != nil {
		t.Fatalf("ordinary shutdown reported as a failure: %v", got)
	}

	// A real one is found behind them rather than hidden by them.
	lost := errors.New("accept tcp 172.17.0.1:4010: use of closed network connection")
	ch <- http.ErrServerClosed
	ch <- lost
	if got := awaitStopped(ch, 2); !errors.Is(got, lost) {
		t.Fatalf("got %v, want %v", got, lost)
	}

	// A result that has not arrived yet is waited for, not missed — the case
	// that made this a wait instead of a peek.
	slow := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		slow <- lost
	}()
	if got := awaitStopped(slow, 1); !errors.Is(got, lost) {
		t.Fatalf("in-flight error missed: got %v", got)
	}
}

// A listener that dies while the daemon is running has to be reported without
// a signal to prompt it — a daemon serving one of two interfaces must not sit
// there until someone stops it.
//
// That is the whole of what this covers, and the whole of what serveListeners
// promises. The near-simultaneous case — a loss still in flight when a shutdown
// begins — is not pinned here or anywhere: http.Server rewrites the accept
// error once Shutdown starts, so the window is inherent. See awaitStopped,
// which says so.
func TestServeReportsALostListener(t *testing.T) {
	srv, _, _, _ := testServer(t)
	listeners, addrs := listenLoopback(t, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveListeners(ctx, listeners, srv.Handler()) }()
	waitReady(t, addrs)

	// Take one listener out from under the daemon: it is now half-listening.
	listeners[1].Close()
	waitGone(t, addrs[1])

	// No cancel. The guarantee under test is that losing a listener is reported
	// on its own, without a signal to prompt it — a daemon serving one of two
	// interfaces must not sit there until someone stops it.
	//
	// Cancelling here instead is what made this test flaky, and the flake was
	// telling the truth: with a signal racing the loss, http.Server rewrites the
	// accept error to ErrServerClosed the moment Shutdown begins, and
	// awaitStopped filters it as an ordinary stop. That window is inherent —
	// see awaitStopped — so a test that opens it deliberately is asserting
	// something the design does not promise. The cancel deferred above is the
	// safety net if serveListeners fails to return at all.
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("clean stop reported for a daemon that had lost a listener")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveListeners did not report a lost listener")
	}
}

// A clean stop is the one exit that returns nil, so it is the one exit whose
// only trace is whatever it logged. It logged nothing until SGNT-19, and the
// gap is what let the daemon vanish twice for days with the journal showing an
// ordinary shutdown. Asserting on the line is asserting the outage is visible.
func TestServeLogsACleanStop(t *testing.T) {
	srv, _, _, _ := testServer(t)
	listeners, addrs := listenLoopback(t, 2)

	logged := logtest.Capture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveListeners(ctx, listeners, srv.Handler()) }()
	waitReady(t, addrs)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("clean stop reported an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveListeners did not return")
	}

	out := logged()
	if !strings.Contains(out, "api stopped") {
		t.Errorf("a clean stop left no record of stopping; log was %q", out)
	}
	// Naming the addresses is what lets an operator line the stop up against
	// the startup line. This asserts they are all named — not that each was
	// individually confirmed closed, which the line does not claim and this
	// test could not check.
	for _, addr := range addrs {
		if !strings.Contains(out, addr) {
			t.Errorf("stop line omits %s; log was %q", addr, out)
		}
	}
}

// reachable reports whether anything accepts a connection on addr.
func reachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// waitReady blocks until every address accepts, not just the first. listenAll
// binds sequentially and a socket accepts the moment net.Listen returns, so
// waiting on one address says nothing about whether the rest exist yet.
func waitReady(t *testing.T, addrs []string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for _, addr := range addrs {
		for !reachable(addr) {
			if time.Now().After(deadline) {
				t.Fatalf("%s never came up", addr)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// waitGone blocks until addr stops accepting.
func waitGone(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for reachable(addr) {
		if time.Now().After(deadline) {
			t.Fatalf("%s still accepting", addr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
