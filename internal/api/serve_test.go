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

// firstUnexpected is what keeps a lost listener from being reported as a clean
// stop when SIGTERM lands at the same moment. It is unit-tested because the
// race it settles cannot be staged through serveListeners: whichever of the
// two select cases is ready first wins, and by construction that is usually
// errCh.
func TestFirstUnexpected(t *testing.T) {
	// An ordinary shutdown is not a failure, however many listeners report it.
	ch := make(chan error, 4)
	ch <- http.ErrServerClosed
	ch <- nil
	ch <- http.ErrServerClosed
	if got := firstUnexpected(ch); got != nil {
		t.Fatalf("ordinary shutdown reported as a failure: %v", got)
	}

	// A real one is found behind them, not hidden by them.
	lost := errors.New("accept tcp 172.17.0.1:4010: use of closed network connection")
	ch <- http.ErrServerClosed
	ch <- lost
	if got := firstUnexpected(ch); !errors.Is(got, lost) {
		t.Fatalf("got %v, want %v", got, lost)
	}

	// And it never blocks on a channel with nothing in it.
	if got := firstUnexpected(make(chan error, 1)); got != nil {
		t.Fatalf("got %v from an empty channel", got)
	}
}

// A listener that dies on its own has to be reported rather than swallowed —
// whichever way the select resolves. Exiting 0 here would sign off as healthy
// a daemon that had been refusing an entire interface.
func TestServeReportsALostListenerOnShutdown(t *testing.T) {
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
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("clean stop reported for a daemon that had lost a listener")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveListeners did not return")
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
