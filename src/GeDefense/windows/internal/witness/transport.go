// STATUS: PLATIN VGT SUPREME

package witness

// Hardened network trust boundary of the witness client.
//
// Three independent checks protect every outbound connection:
//
//  1. certificate pinning: the SHA-256 over the server certificate's
//     RawSubjectPublicKeyInfo must equal the configured SPKI pin (constant time),
//     checked inside the TLS handshake and again on every injected transport;
//  2. destination guarding: only https on port 443, no environment proxy, and the
//     resolved peer address must not be loopback, link-local, private, multicast
//     or a cloud metadata endpoint unless the operator explicitly allowed private
//     destinations; after DialContext the actually connected RemoteAddr is
//     re-checked, which defeats DNS rebinding;
//  3. no redirects and no InsecureSkipVerify: redirects are refused by the HTTP
//     client, TLS >= 1.2 and the system trust store stay enabled.
//
// Nothing in this file logs, returns or stores an endpoint, token or key.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

var (
	// ErrSPKIPinMismatch marks a peer certificate that does not match the pin.
	ErrSPKIPinMismatch = errors.New("witness server certificate SPKI pin mismatch")
	// ErrCertificateInvalid marks a peer certificate the system trust store or
	// hostname verification rejected. It is never retried.
	ErrCertificateInvalid = errors.New("witness server certificate is invalid")
	// ErrDestinationRefused marks a forbidden network destination.
	ErrDestinationRefused = errors.New("witness destination is refused")
)

// spkiPinMatches compares the certificate SPKI hash with the pin in constant
// time. It is the single pin predicate of the package.
func spkiPinMatches(pin []byte, certificate *x509.Certificate) bool {
	if len(pin) != sha256.Size || certificate == nil {
		return false
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return subtle.ConstantTimeCompare(digest[:], pin) == 1
}

// pinVerifyingTransport re-checks the SPKI pin for an injected RoundTripper. The
// production transport pins during the handshake; this wrapper is the second line
// of defence and the only pin path for test transports.
type pinVerifyingTransport struct {
	base http.RoundTripper
	pin  []byte
}

func (transport *pinVerifyingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if len(transport.pin) != 0 {
		if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 ||
			!spkiPinMatches(transport.pin, response.TLS.PeerCertificates[0]) {
			_ = response.Body.Close()
			return nil, ErrSPKIPinMismatch
		}
	}
	return response, nil
}

// dialGuard resolves a hostname, filters forbidden addresses before dialing and
// re-checks the actually connected peer address afterwards.
type dialGuard struct {
	dialer       *net.Dialer
	resolver     *net.Resolver
	allowPrivate bool
}

// DialContext implements the guarded dial function of the production transport.
func (guard *dialGuard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, fmt.Errorf("%w: destination is not https port 443", ErrDestinationRefused)
	}
	if err := validateEndpointHost(host, guard.allowPrivate); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDestinationRefused, err)
	}
	resolved, err := guard.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(resolved) == 0 {
		return nil, fmt.Errorf("%w: destination resolution failed", ErrDestinationRefused)
	}
	candidates := make([]netip.Addr, 0, len(resolved))
	for _, candidate := range resolved {
		address, ok := netip.AddrFromSlice(candidate.IP)
		if !ok || forbiddenDestinationIP(address, guard.allowPrivate) {
			continue
		}
		candidates = append(candidates, address.Unmap())
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: destination resolves only to forbidden addresses", ErrDestinationRefused)
	}
	var lastErr error
	for _, candidate := range candidates {
		connection, dialErr := guard.dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		remote, ok := connection.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = connection.Close()
			return nil, fmt.Errorf("%w: connected peer has no IP address", ErrDestinationRefused)
		}
		remoteAddress, ok := netip.AddrFromSlice(remote.IP)
		if !ok || forbiddenDestinationIP(remoteAddress, guard.allowPrivate) {
			_ = connection.Close()
			return nil, fmt.Errorf("%w: connected peer address is forbidden", ErrDestinationRefused)
		}
		return connection, nil
	}
	if lastErr == nil {
		return nil, fmt.Errorf("%w: no candidate address is dialable", ErrDestinationRefused)
	}
	return nil, lastErr
}

// buildHardenedTransport returns the production HTTP transport. Proxy is
// explicitly nil (no http_proxy/https_proxy from the environment), TLS >= 1.2,
// system certificate verification stays enabled and the SPKI pin is checked inside
// the handshake before any request body can be written.
func buildHardenedTransport(pin []byte, timeout time.Duration, allowPrivate bool) *http.Transport {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !spkiPinMatches(pin, state.PeerCertificates[0]) {
				return ErrSPKIPinMismatch
			}
			return nil
		},
	}
	guard := &dialGuard{
		dialer:       &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second},
		resolver:     net.DefaultResolver,
		allowPrivate: allowPrivate,
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           guard.DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}
