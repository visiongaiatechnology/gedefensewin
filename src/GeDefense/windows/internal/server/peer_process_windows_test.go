// STATUS: PLATIN
//go:build windows

package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestPeerProcessLookupResolvesLoopbackOwner exercises the real
// GetExtendedTcpTable path against a loopback test listener: the owning process
// of the client socket must be this test process.
func TestPeerProcessLookupResolvesLoopbackOwner(t *testing.T) {
	remoteAddresses := make(chan string, 1)
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case remoteAddresses <- r.RemoteAddr:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer testServer.Close()

	listener, ok := testServer.Listener.Addr().(*net.TCPAddr)
	if !ok || listener.Port < 1 {
		t.Fatal("test listener address unavailable")
	}
	response, err := http.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_ = response.Body.Close()
	var remoteAddress string
	select {
	case remoteAddress = <-remoteAddresses:
	default:
		t.Fatal("test server did not observe a loopback request")
	}
	pid, err := lookupPeerProcessIDForPort(remoteAddress, uint16(listener.Port))
	if err != nil {
		t.Fatalf("peer process lookup failed: %v", err)
	}
	if pid != uint32(os.Getpid()) {
		t.Fatalf("peer pid=%d, want %d", pid, os.Getpid())
	}
}

func TestProcessAncestryHelpersFailClosed(t *testing.T) {
	ownPID := uint32(os.Getpid())
	if !processDescendsFrom(ownPID, ownPID) {
		t.Fatal("a process must be considered its own ancestry root")
	}
	if processDescendsFrom(ownPID, 0) {
		t.Fatal("null parent pid accepted")
	}
	if processDescendsFrom(0, ownPID) {
		t.Fatal("null child pid accepted")
	}
	if processDescendsFrom(ownPID, ^uint32(0)) {
		t.Fatal("impossible ancestor accepted")
	}
}
