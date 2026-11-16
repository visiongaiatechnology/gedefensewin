// STATUS: PLATIN
package server

import (
	"log"
	"net"
	"net/http"
	"path/filepath"
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
	// The broker caller must be one of the installed product binaries. The
	// filename is bound to the requested client so a Tray process cannot claim
	// the Center role (FIND-WIN-006). The image path itself must additionally be
	// inside the installed product tree and carry a valid Authenticode signature;
	// both checks are performed by the Windows operator-peer resolver.
	operatorCenterExecutable = "gedefensecenter.exe"
	operatorTrayExecutable   = "gedefensetray.exe"
	// maxOperatorBrokerBody is the only body shape the broker accepts (one short
	// client name). The broker is a credential-issuing endpoint, so it stays
	// deliberately minimal.
	maxOperatorBrokerBody = 1024
)

// operatorPeer is the verified Windows OS identity of a loopback caller. It is
// produced by operatorPeerFromPID (Windows token + process image inspection) and
// is never accepted from request data.
type operatorPeer struct {
	PID           uint32
	Account       string
	SID           string
	Administrator bool
	Operator      bool
	// Elevated reports the peer token's elevation state (TokenElevation). It
	// bounds the scopes a broker client may receive: policy/window authority is
	// only granted to an elevated token (FIND-WIN-006).
	Elevated bool
	// ImagePath is the kernel-reported image path of the calling process
	// (QueryFullProcessImageNameW). Empty means the peer could not be identified
	// and the broker fails closed.
	ImagePath string
	// ImageTrusted reports that ImagePath is inside the installed product tree
	// and reparse-free (trust.Default().TrustedTreePath).
	ImageTrusted bool
	// ImageSignatureVerified reports a successful Authenticode check of the
	// installed image. Unsigned/development builds leave this false and the
	// broker fails closed by design; there is no silent bypass.
	ImageSignatureVerified bool
}

func (p operatorPeer) authorised() bool {
	return p.Operator || p.Administrator
}

// imageAuthorisedFor binds the broker client role to the verified executable of
// the calling process. The client name in the request body can only select a
// role that the actual binary already is; it can never upgrade it. The image
// must resolve inside the installed product tree and pass Authenticode, and the
// filename must match the role exactly (exact basenames, case-insensitive).
func (p operatorPeer) imageAuthorisedFor(client string) bool {
	if !p.ImageTrusted || !p.ImageSignatureVerified || strings.TrimSpace(p.ImagePath) == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(p.ImagePath)))
	switch client {
	case operatorBrokerCenter:
		return base == operatorCenterExecutable
	case operatorBrokerTray:
		return base == operatorTrayExecutable
	default:
		return false
	}
}

// operatorScopesFor derives the session scopes server-side from the verified
// binary and token. A client header can never raise them. The Tray is always
// read-only. The Center gets policy/window authority only with an elevated token;
// a medium-IL Center is bounded to read+operate (FIND-WIN-006).
func operatorScopesFor(client string, peer operatorPeer) scope {
	switch client {
	case operatorBrokerCenter:
		if peer.Elevated {
			return scopeAll
		}
		return scopeRead | scopeOperate
	case operatorBrokerTray:
		return scopeRead
	default:
		return 0
	}
}

type operatorBrokerRequest struct {
	Client string `json:"client"`
}

// operatorBroker is the local replacement for reading the long-lived master
// token file from Center and Tray (UI-FIND-001 / AN-FIND-004 / AN-FIND-001).
// It is intentionally unauthenticated at the HTTP layer but bound to a verified
// local OS process identity:
//
//   - only a loopback peer is accepted (the outer headers wrapper enforces Host
//     and RemoteAddr, and this handler re-resolves the peer process id),
//   - the peer process token must be a member of the local "VGT GeDefense
//     Operators" group or Administrators; the token is inspected, never a
//     client-supplied claim,
//   - the peer image must be the signed, installed Center or Tray binary and the
//     requested client role must match that binary (FIND-WIN-006),
//   - browser requests are rejected (custom header required, Origin/Referer
//     must be absent, an Authorization header or VGTSESSION cookie is refused),
//   - peer authentication/authorisation happens BEFORE the rate budget and the
//     replay guard; unauthorised attempts are counted in their own bucket so
//     they can never lock out the legitimate operator (FIND-WIN-008),
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
	if client != operatorBrokerCenter && client != operatorBrokerTray {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	remoteHost := remoteHostOf(r)
	// Authenticate the caller first: only a verified peer may ever draw from the
	// authorized broker budget or a replay slot.
	peer, allowed := s.authoriseOperatorCaller(r, client)
	if !allowed {
		s.rejectOperatorCaller(w, remoteHost)
		return
	}
	if !s.allowRate("operator-broker:"+remoteHost, ratePolicy) {
		w.Header().Set("Retry-After", "5")
		s.writeError(w, http.StatusTooManyRequests, "request rate limited")
		return
	}
	if !s.claim(r.Header.Get("X-VGT-Request-ID")) {
		s.writeError(w, http.StatusConflict, "request rejected")
		return
	}
	scopes := operatorScopesFor(client, peer)
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
		"; elevated=" + boolText(peer.Elevated) +
		"; image=" + filepath.Base(peer.ImagePath) +
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

// authoriseOperatorCaller resolves the peer process of this connection and
// proves it is an authorised operator whose installed image matches the
// requested client role. Every error, missing pid or missing image path fails
// closed; there is no default scope and no dev bypass.
func (s *Server) authoriseOperatorCaller(r *http.Request, client string) (operatorPeer, bool) {
	peerPID, err := s.peerProcessID(r.RemoteAddr)
	if err != nil || peerPID == 0 {
		log.Printf("operator broker: peer process lookup failed")
		return operatorPeer{}, false
	}
	peer, err := s.resolveOperatorPeer(peerPID)
	if err != nil || !peer.authorised() || strings.TrimSpace(peer.Account) == "" {
		log.Printf("operator broker: peer identity rejected")
		return operatorPeer{}, false
	}
	if !peer.imageAuthorisedFor(client) {
		log.Printf("operator broker: caller image rejected")
		return operatorPeer{}, false
	}
	return peer, true
}

// rejectOperatorCaller counts an unauthorised broker attempt in a dedicated
// bucket. The authorized "operator-broker:" budget and the replay table stay
// untouched, so an unauthorised user cannot lock out Center/Tray (FIND-WIN-008).
func (s *Server) rejectOperatorCaller(w http.ResponseWriter, remoteHost string) {
	if !s.allowRate("operator-broker-rejected:"+remoteHost, rateBrokerRejected) {
		w.Header().Set("Retry-After", "5")
		s.writeError(w, http.StatusTooManyRequests, "request rate limited")
		return
	}
	s.writeError(w, http.StatusForbidden, "request rejected")
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
