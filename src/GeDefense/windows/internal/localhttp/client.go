// STATUS: DIAMANT VGT SUPREME
package localhttp

import (
	"errors"
	"net"
	"net/http"
	"time"
)

// NewClient returns an HTTP client for the GeDefense loopback control plane.
// It never consults environment proxy variables and never follows redirects.
func NewClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirect rejected by local control-plane client")
		},
	}
}
