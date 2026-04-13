package vasign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Sentinel errors returned by Verifier.Verify.
var (
	ErrMissingHeader    = errors.New("vasign: missing required auth header")
	ErrInvalidTimestamp = errors.New("vasign: invalid timestamp")
	ErrExpiredTimestamp = errors.New("vasign: timestamp outside allowed window")
	ErrBodyTooLarge    = errors.New("vasign: request body exceeds size limit")
	ErrInvalidSignature = errors.New("vasign: signature verification failed")
)

const (
	defaultTimeWindow  = 5 * time.Minute
	defaultMaxBodySize = 1 << 20 // 1 MB
)

// VerifiedRequest contains the parsed authentication headers from a
// successfully verified request. Callers can use these fields to perform
// application-level checks such as key lookup and nonce deduplication.
type VerifiedRequest struct {
	ClientID  string
	KeyID     string
	Timestamp time.Time
	Nonce     string
}

// Verifier verifies Ed25519 request signatures produced by Signer.
//
// Verifier is safe for concurrent use by multiple goroutines.
type Verifier struct {
	timeWindow  time.Duration
	maxBodySize int64
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithTimeWindow sets the maximum allowed age of a request timestamp.
// Both past and future drift are checked against this window.
// Set to 0 to disable timestamp checking. Negative values are treated as 0.
// The default is 5 minutes.
func WithTimeWindow(d time.Duration) VerifierOption {
	return func(v *Verifier) { v.timeWindow = max(d, 0) }
}

// WithMaxBodySize sets the maximum request body size in bytes that the
// verifier will read. If the body exceeds this limit, Verify returns
// ErrBodyTooLarge. Set to 0 to disable the limit. The default is 1 MB.
func WithMaxBodySize(n int64) VerifierOption {
	return func(v *Verifier) { v.maxBodySize = n }
}

// NewVerifier creates a Verifier with the given options.
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{
		timeWindow:  defaultTimeWindow,
		maxBodySize: defaultMaxBodySize,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify checks the Ed25519 signature on req using publicKey.
//
// It extracts the five authentication headers (X-Client-Id, X-Key-Id,
// X-Timestamp, X-Nonce, X-Signature), validates the timestamp falls within
// the configured time window, reads the body (up to the configured size limit),
// reconstructs the canonical signing string, and verifies the signature.
//
// After Verify returns the request body is still readable regardless of
// whether verification succeeded or failed.
//
// Verify does NOT perform key lookup or nonce deduplication — those are
// application-level concerns. The returned VerifiedRequest provides the
// parsed header values so callers can implement their own checks.
func (v *Verifier) Verify(req *http.Request, publicKey ed25519.PublicKey) (vr *VerifiedRequest, err error) {
	clientID := req.Header.Get(HeaderClientID)
	keyID := req.Header.Get(HeaderKeyID)
	timestampRaw := req.Header.Get(HeaderTimestamp)
	nonce := req.Header.Get(HeaderNonce)
	signatureRaw := req.Header.Get(HeaderSignature)

	if clientID == "" || keyID == "" || timestampRaw == "" || nonce == "" || signatureRaw == "" {
		missing := ""
		switch {
		case clientID == "":
			missing = HeaderClientID
		case keyID == "":
			missing = HeaderKeyID
		case timestampRaw == "":
			missing = HeaderTimestamp
		case nonce == "":
			missing = HeaderNonce
		case signatureRaw == "":
			missing = HeaderSignature
		}
		err = fmt.Errorf("%w: %s", ErrMissingHeader, missing)
		return
	}

	timestamp, parseErr := strconv.ParseInt(timestampRaw, 10, 64)
	if parseErr != nil {
		err = fmt.Errorf("%w: %v", ErrInvalidTimestamp, parseErr)
		return
	}

	requestTime := time.Unix(timestamp, 0)
	now := time.Now()
	if v.timeWindow > 0 {
		if now.Sub(requestTime) > v.timeWindow || requestTime.Sub(now) > v.timeWindow {
			err = ErrExpiredTimestamp
			return
		}
	}

	var bodyBytes []byte
	if req.Body != nil {
		var reader io.Reader = req.Body
		if v.maxBodySize > 0 {
			reader = io.LimitReader(req.Body, v.maxBodySize+1)
		}
		bodyBytes, err = io.ReadAll(reader)
		req.Body.Close()
		if err != nil {
			err = fmt.Errorf("vasign: read body: %w", err)
			return
		}
		if v.maxBodySize > 0 && int64(len(bodyBytes)) > v.maxBodySize {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			err = ErrBodyTooLarge
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	bodyHash := sha256.Sum256(bodyBytes)

	path := ""
	rawQuery := ""
	if req.URL != nil {
		path = req.URL.EscapedPath()
		rawQuery = req.URL.RawQuery
	}

	signingString := req.Method + "\n" +
		path + "\n" +
		rawQuery + "\n" +
		timestampRaw + "\n" +
		nonce + "\n" +
		hex.EncodeToString(bodyHash[:])

	signature, decErr := base64.StdEncoding.DecodeString(signatureRaw)
	if decErr != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, []byte(signingString), signature) {
		err = ErrInvalidSignature
		return
	}

	vr = &VerifiedRequest{
		ClientID:  clientID,
		KeyID:     keyID,
		Timestamp: requestTime,
		Nonce:     nonce,
	}
	return
}
