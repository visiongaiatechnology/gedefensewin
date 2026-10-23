// STATUS: PLATIN
package server

import (
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	// operatorBrokerHeader is a non-secret capability marker. It forces custom
	// header semantics so a browser cannot reach the broker with a simple
	// cross-origin form/fetch request; combined with the Origin rejection below
	// and the absent CORS layer this is not a CSRF surface.
	operatorBrokerHeader = "X-VGT-Operator-Broker"
	operatorBrokerValue  = "1"
	// operatorBrokerCenter is the window-host client. It needs the full operator
	// scope set (read/operate/policy/window) to drive the console and register
	// its browser child process.
	operatorBrokerCenter = "center-launcher"
	// operatorBrokerTray is the notification-area client. It only needs read
	// access and never receives operate/policy/window authority.
	operatorBrokerTray = "tray"
	// maxOperatorBrokerBody is the only body shape the broker accepts (one short
	// client name). The broker is a credential-issuing endpoint, so it stays
	// deliberately minimal.
	maxOperatorBrokerBody = 1024
)

// operatorPeer is the verified Windows OS identity of a loopback caller. It is
// produced by operatorPeerFromPID (Windows token inspection) and is never
// accepted from request data.
type operatorPeer struct {
	PID           uint32
	Account       string
	SID           string
	Administrator bool
	Operator      bool
}

func (p operatorPeer) authorised() bool {
	return p.Operator || p.Administrator
}

type operatorBrokerRequest struct {
	Client string `json:"client"`
}

// operatorBroker is the local replacement for reading the long-lived master
// token file from Center and Tray (UI-FIND-001 / AN-FIND-004 / AN-FIND-001).
// It is intentionally unauthenticated at the HTTP layer but bound to a verified
// local OS process token:
//
//   - only a loopback peer is accepted (the outer headers wrapper enforces Host
//     and RemoteAddr, and this handler re-resolves the peer process id),
//   - the peer process token must be a member of the local "VGT GeDefense
//     Operators" group or Administrators; the token is inspected, never a
//     client-supplied claim,
//   - browser requests are rejected (custom header required, Origin/Referer
//     must be absent, an Authorization header or VGTSESSION cookie is refused),
//   - the request carries the mandatory replay id like every other mutation,
//   - the minted session is short-lived, scoped, auditable and revocable, and
//     the master token file never leaves the service process.
func (s *Server) operatorBroker(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(operatorBrokerHeader) != operatorBrokerValue {
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	if r.Header.Get("Origin") != "" || r.Header.Get("Referer") != "" {
		// A browser console/fetch would carry Origin; the broker is only for
		// native local processes.
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	if r.Header.Get("Authorization") != "" {
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	if _, err := r.Cookie("VGTSESSION"); err == nil {
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	var input operatorBrokerRequest
	if err := decodeJSONBounded(w, r, &input, maxOperatorBrokerBody); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	client := strings.TrimSpace(input.Client)
	var scopes scope
	switch client {
	case operatorBrokerCenter:
		scopes = scopeAll
	case operatorBrokerTray:
		scopes = scopeRead
	default:
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	remoteHost := remoteHostOf(r)
	if !s.allowRate("operator-broker:"+remoteHost, ratePolicy) {
		w.Header().Set("Retry-After", "5")
		s.writeError(w, http.StatusTooManyRequests, "request rate limited")
		return
	}
	if !s.claim(r.Header.Get("X-VGT-Request-ID")) {
		s.writeError(w, http.StatusConflict, "request rejected")
		return
	}
	peerPID, err := s.peerProcessID(r.RemoteAddr)
	if err != nil || peerPID == 0 {
		log.Printf("operator broker: peer process lookup failed")
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	peer, err := s.resolveOperatorPeer(peerPID)
	if err != nil || !peer.authorised() || strings.TrimSpace(peer.Account) == "" {
		log.Printf("operator broker: peer identity rejected")
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	now := s.clock()
	s.sessionMu.Lock()
	s.purgeSessionsLocked(now)
	token, record, err := s.createOperatorSessionLocked(now, client, scopes, peer)
	s.sessionMu.Unlock()
	if err != nil {
		log.Printf("operator broker: session creation failed: %v", err)
		s.writeError(w, http.StatusServiceUnavailable, "session initialization failed")
		return
	}
	detail := "created:operator-broker; client=" + client +
		"; account=" + peer.Account +
		"; administrator=" + boolText(peer.Administrator) +
		"; operator=" + boolText(peer.Operator) +
		"; scopes=" + strings.Join(scopes.names(), ",") +
		"; session=" + sessionDigest(token)
	if s.ledger != nil {
		if appendErr := s.ledger.Append("session.lifecycle", "operator-broker", detail); appendErr != nil {
			log.Printf("operator broker evidence: %v", appendErr)
		}
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"token":      token,
		"client":     client,
		"scopes":     scopes.names(),
		"expiresUtc": record.expires.UTC(),
		"subject": map[string]any{
			"account":       peer.Account,
			"administrator": peer.Administrator,
			"operator":      peer.Operator,
		},
	})
}

// createOperatorSessionLocked mints an operator session bound to the verified
// OS identity. The caller holds sessionMu.
func (s *Server) createOperatorSessionLocked(now time.Time, client string, scopes scope, peer operatorPeer) (string, *sessionRecord, error) {
	token, record, err := s.createSessionLocked(now, client, scopes, sessionAbsoluteLifetime)
	if err != nil {
		return "", nil, err
	}
	record.operator = true
	record.subjectAccount = peer.Account
	record.subjectSID = peer.SID
	return token, record, nil
}

func remoteHostOf(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return remoteHost
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
