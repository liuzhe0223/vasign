package vasign

import (
	"fmt"
	"net/http"
)

// Transport is an http.RoundTripper that automatically signs every outgoing request.
//
// Transport is safe for concurrent use by multiple goroutines.
type Transport struct {
	signer *Signer
	base   http.RoundTripper
}

// NewTransport wraps a base RoundTripper with automatic request signing.
// If base is nil, http.DefaultTransport is used.
func NewTransport(signer *Signer, base http.RoundTripper) (t *Transport) {
	if signer == nil {
		panic("vasign: NewTransport called with nil signer")
	}
	if base == nil {
		base = http.DefaultTransport
	}
	t = &Transport{signer: signer, base: base}
	return
}

// RoundTrip clones the request, signs the clone, and delegates to the base transport.
// The original request headers are never modified, per the http.RoundTripper contract.
// Note: if the original request was constructed without GetBody (i.e. not via
// http.NewRequest), the body io.ReadCloser is shared between original and clone;
// Sign will consume it.
func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	req2 := req.Clone(req.Context())
	if err = t.signer.Sign(req2); err != nil {
		err = fmt.Errorf("vasign: sign request: %w", err)
		return
	}
	resp, err = t.base.RoundTrip(req2)
	return
}
