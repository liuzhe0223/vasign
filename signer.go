// Package vasign provides Ed25519 HTTP request signing and verification helpers.
//
// The signing scheme constructs a canonical string from the request method, path,
// query string, a Unix timestamp, a random nonce, and the SHA-256 hex digest of
// the request body, then signs it with Ed25519. Five headers are added to the
// request: X-Client-Id, X-Key-Id, X-Timestamp, X-Nonce, and X-Signature.
//
// Signer is safe for concurrent use by multiple goroutines.
package vasign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	HeaderClientID  = "X-Client-Id"
	HeaderKeyID     = "X-Key-Id"
	HeaderTimestamp = "X-Timestamp"
	HeaderNonce     = "X-Nonce"
	HeaderSignature = "X-Signature"
)

// Signer signs outgoing HTTP requests for API authentication.
//
// Signer is safe for concurrent use by multiple goroutines.
type Signer struct {
	clientID   string
	keyID      string
	privateKey ed25519.PrivateKey
}

// NewSigner creates a Signer from raw Ed25519 private key bytes.
func NewSigner(clientID, keyID string, privateKey ed25519.PrivateKey) (s *Signer, err error) {
	if clientID == "" {
		err = fmt.Errorf("vasign: client_id is required")
		return
	}
	if keyID == "" {
		err = fmt.Errorf("vasign: key_id is required")
		return
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		hint := ""
		if len(privateKey) == ed25519.SeedSize {
			hint = " (did you mean NewSignerFromSeed?)"
		}
		err = fmt.Errorf("vasign: invalid private key size: got %d, want %d%s", len(privateKey), ed25519.PrivateKeySize, hint)
		return
	}
	s = &Signer{clientID: clientID, keyID: keyID, privateKey: privateKey}
	return
}

// NewSignerFromBase64 creates a Signer from a base64-encoded Ed25519 private key (64 bytes decoded).
func NewSignerFromBase64(clientID, keyID, privateKeyBase64 string) (s *Signer, err error) {
	raw, decErr := base64.StdEncoding.DecodeString(privateKeyBase64)
	if decErr != nil {
		err = fmt.Errorf("vasign: decode base64 private key: %w", decErr)
		return
	}
	return NewSigner(clientID, keyID, ed25519.PrivateKey(raw))
}

// NewSignerFromSeed creates a Signer from a 32-byte Ed25519 seed (base64-encoded).
func NewSignerFromSeed(clientID, keyID, seedBase64 string) (s *Signer, err error) {
	seed, decErr := base64.StdEncoding.DecodeString(seedBase64)
	if decErr != nil {
		err = fmt.Errorf("vasign: decode base64 seed: %w", decErr)
		return
	}
	if len(seed) != ed25519.SeedSize {
		err = fmt.Errorf("vasign: invalid seed size: got %d, want %d", len(seed), ed25519.SeedSize)
		return
	}
	return NewSigner(clientID, keyID, ed25519.NewKeyFromSeed(seed))
}

// Sign adds authentication headers to req and replaces req.Body with a fresh
// reader containing the same bytes. The request body must be set before calling
// Sign; if body is nil, an empty body is assumed. After Sign returns the body is
// still readable, but the original Body io.ReadCloser is consumed.
func (s *Signer) Sign(req *http.Request) (err error) {
	if req.URL == nil {
		err = fmt.Errorf("vasign: request URL is nil")
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}

	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			err = fmt.Errorf("vasign: read body: %w", err)
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, nonceErr := generateNonce()
	if nonceErr != nil {
		err = fmt.Errorf("vasign: generate nonce: %w", nonceErr)
		return
	}

	bodyHash := sha256.Sum256(bodyBytes)
	signingString := req.Method + "\n" +
		req.URL.EscapedPath() + "\n" +
		req.URL.RawQuery + "\n" +
		timestamp + "\n" +
		nonce + "\n" +
		hex.EncodeToString(bodyHash[:])

	signature := ed25519.Sign(s.privateKey, []byte(signingString))

	req.Header.Set(HeaderClientID, s.clientID)
	req.Header.Set(HeaderKeyID, s.keyID)
	req.Header.Set(HeaderTimestamp, timestamp)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	return
}

// PublicKey returns the Ed25519 public key derived from the signer's private key.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.privateKey.Public().(ed25519.PublicKey)
}

// PublicKeyBase64 returns the base64-encoded public key.
func (s *Signer) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.PublicKey())
}

func generateNonce() (nonce string, err error) {
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return
	}
	nonce = hex.EncodeToString(b)
	return
}
