package api

import (
	"context"
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
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, addrs, srv) }()
	waitReady(t, addrs[0])

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

// reachable reports whether anything accepts a connection on addr.
func reachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func waitReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if reachable(addr) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never came up", addr)
}
