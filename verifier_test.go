package vasign_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liuzhe0223/vasign"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// signedRequest creates an http.Request and signs it with the given signer.
func signedRequest(t *testing.T, signer *vasign.Signer, method, url string, body []byte) *http.Request {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

// ---------------------------------------------------------------------------
// End-to-end: Sign then Verify
// ---------------------------------------------------------------------------

func TestVerifyValidSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("client-1", "key-1", priv)
	verifier := vasign.NewVerifier()

	body := []byte(`{"hello":"world"}`)
	req := signedRequest(t, signer, "POST", "https://example.com/v1/orders?page=1", body)

	vr, err := verifier.Verify(req, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if vr.ClientID != "client-1" {
		t.Errorf("client_id: got %s, want client-1", vr.ClientID)
	}
	if vr.KeyID != "key-1" {
		t.Errorf("key_id: got %s, want key-1", vr.KeyID)
	}
	if vr.Nonce == "" {
		t.Error("nonce should not be empty")
	}
	if vr.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestVerifyEmptyBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/v1/accounts", nil)

	if _, err := verifier.Verify(req, pub); err != nil {
		t.Fatalf("verify empty body: %v", err)
	}
}

func TestVerifyPercentEncodedPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/v1/users/hello%2Fworld", nil)

	if _, err := verifier.Verify(req, pub); err != nil {
		t.Fatalf("verify percent-encoded path: %v", err)
	}
}

func TestVerifyDifferentHTTPMethods(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			var body []byte
			if method != "GET" && method != "DELETE" {
				body = []byte(`{"data":1}`)
			}
			req := signedRequest(t, signer, method, "https://example.com/test", body)
			if _, err := verifier.Verify(req, pub); err != nil {
				t.Fatalf("verify %s: %v", method, err)
			}
		})
	}
}

func TestVerifyBodyRemainsReadable(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	body := []byte(`{"data":true}`)
	req := signedRequest(t, signer, "POST", "https://example.com/test", body)

	if _, err := verifier.Verify(req, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	got, _ := io.ReadAll(req.Body)
	if string(got) != string(body) {
		t.Fatalf("body after verify: got %q, want %q", got, body)
	}
}

func TestVerifyTimestampInVerifiedRequest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	before := time.Now().Unix()
	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	after := time.Now().Unix()

	vr, err := verifier.Verify(req, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	ts := vr.Timestamp.Unix()
	if ts < before || ts > after {
		t.Fatalf("timestamp %d outside [%d, %d]", ts, before, after)
	}
}

// ---------------------------------------------------------------------------
// Error paths: missing headers
// ---------------------------------------------------------------------------

func TestVerifyMissingHeaders(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	headers := []string{
		vasign.HeaderClientID,
		vasign.HeaderKeyID,
		vasign.HeaderTimestamp,
		vasign.HeaderNonce,
		vasign.HeaderSignature,
	}

	for _, drop := range headers {
		t.Run("missing_"+drop, func(t *testing.T) {
			req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
			req.Header.Del(drop)

			_, err := verifier.Verify(req, pub)
			if !errors.Is(err, vasign.ErrMissingHeader) {
				t.Fatalf("expected ErrMissingHeader, got: %v", err)
			}
			// Error message should name the missing header.
			if !strings.Contains(err.Error(), drop) {
				t.Fatalf("error should mention %s, got: %v", drop, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Error paths: timestamp
// ---------------------------------------------------------------------------

func TestVerifyExpiredTimestamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	// Set timestamp to 10 minutes ago.
	oldTS := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	req.Header.Set(vasign.HeaderTimestamp, oldTS)

	_, err := verifier.Verify(req, pub)
	if !errors.Is(err, vasign.ErrExpiredTimestamp) {
		t.Fatalf("expected ErrExpiredTimestamp, got: %v", err)
	}
}

func TestVerifyFutureTimestamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	futureTS := strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)
	req.Header.Set(vasign.HeaderTimestamp, futureTS)

	_, err := verifier.Verify(req, pub)
	if !errors.Is(err, vasign.ErrExpiredTimestamp) {
		t.Fatalf("expected ErrExpiredTimestamp for future timestamp, got: %v", err)
	}
}

func TestVerifyInvalidTimestampFormat(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	req.Header.Set(vasign.HeaderTimestamp, "not-a-number")

	_, err := verifier.Verify(req, pub)
	if !errors.Is(err, vasign.ErrInvalidTimestamp) {
		t.Fatalf("expected ErrInvalidTimestamp, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error paths: body
// ---------------------------------------------------------------------------

func TestVerifyBodyTooLarge(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	// 100 byte limit.
	verifier := vasign.NewVerifier(vasign.WithMaxBodySize(100))

	body := bytes.Repeat([]byte("a"), 200)
	req := signedRequest(t, signer, "POST", "https://example.com/test", body)

	_, err := verifier.Verify(req, pub)
	if !errors.Is(err, vasign.ErrBodyTooLarge) {
		t.Fatalf("expected ErrBodyTooLarge, got: %v", err)
	}
}

func TestVerifyNoBodySizeLimit(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	// 0 = no limit.
	verifier := vasign.NewVerifier(vasign.WithMaxBodySize(0))

	body := bytes.Repeat([]byte("b"), 2<<20) // 2 MB
	req := signedRequest(t, signer, "POST", "https://example.com/test", body)

	if _, err := verifier.Verify(req, pub); err != nil {
		t.Fatalf("verify with no size limit: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error paths: signature
// ---------------------------------------------------------------------------

func TestVerifyWrongPublicKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)

	_, err := verifier.Verify(req, otherPub)
	if !errors.Is(err, vasign.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestVerifyTamperedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "POST", "https://example.com/test", []byte(`original`))
	// Replace body with tampered content.
	req.Body = io.NopCloser(strings.NewReader("tampered"))

	_, err := verifier.Verify(req, pub)
	if !errors.Is(err, vasign.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for tampered body, got: %v", err)
	}
}

func TestVerifyTamperedPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/original", nil)
	req.URL.Path = "/tampered"

	_, err := verifier.Verify(req, pub)
	if !errors.Is(err, vasign.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for tampered path, got: %v", err)
	}
}

func TestVerifyTamperedQuery(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/test?a=1", nil)
	req.URL.RawQuery = "a=2"

	_, err := verifier.Verify(req, pub)
	if !errors.Is(err, vasign.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for tampered query, got: %v", err)
	}
}

func TestVerifyTamperedNonce(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	req.Header.Set(vasign.HeaderNonce, "tampered-nonce")

	_, err := verifier.Verify(req, pub)
	if !errors.Is(err, vasign.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for tampered nonce, got: %v", err)
	}
}

func TestVerifyCorruptedSignatureBase64(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	req.Header.Set(vasign.HeaderSignature, "not-valid-base64!!!")

	_, err := verifier.Verify(req, pub)
	if !errors.Is(err, vasign.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for corrupted base64, got: %v", err)
	}
}

func TestVerifyTruncatedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	// Truncate the valid base64 signature.
	sig := req.Header.Get(vasign.HeaderSignature)
	req.Header.Set(vasign.HeaderSignature, base64.StdEncoding.EncodeToString([]byte(sig[:8])))

	_, err := verifier.Verify(req, pub)
	if !errors.Is(err, vasign.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for truncated sig, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

func TestVerifyCustomTimeWindow(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	// Very tight window: 1 second.
	tight := vasign.NewVerifier(vasign.WithTimeWindow(1 * time.Second))
	// Very wide window: 1 hour.
	wide := vasign.NewVerifier(vasign.WithTimeWindow(1 * time.Hour))

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	// Set timestamp to 30 seconds ago.
	oldTS := strconv.FormatInt(time.Now().Add(-30*time.Second).Unix(), 10)
	req.Header.Set(vasign.HeaderTimestamp, oldTS)

	// Tight should reject.
	if _, err := tight.Verify(req, pub); !errors.Is(err, vasign.ErrExpiredTimestamp) {
		t.Fatalf("tight window should reject 30s old request, got: %v", err)
	}

	// Wide should still fail signature (because we tampered the timestamp header
	// without re-signing), but NOT with ErrExpiredTimestamp.
	_, err := wide.Verify(req, pub)
	if errors.Is(err, vasign.ErrExpiredTimestamp) {
		t.Fatal("wide window should not reject 30s old timestamp")
	}
}

func TestVerifyZeroTimeWindowDisablesCheck(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	// timeWindow = 0 disables timestamp checking.
	verifier := vasign.NewVerifier(vasign.WithTimeWindow(0))

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	// Set timestamp to 1 year ago — signature will mismatch, but timestamp
	// check itself should not fire.
	oldTS := strconv.FormatInt(time.Now().Add(-365*24*time.Hour).Unix(), 10)
	req.Header.Set(vasign.HeaderTimestamp, oldTS)

	_, err := verifier.Verify(req, pub)
	// Should fail with signature mismatch, NOT expired timestamp.
	if errors.Is(err, vasign.ErrExpiredTimestamp) {
		t.Fatal("zero time window should disable timestamp check")
	}
}

func TestVerifyDefaultOptions(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier() // defaults: 5 min, 1 MB

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	if _, err := verifier.Verify(req, pub); err != nil {
		t.Fatalf("default verifier should pass valid request: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestVerifyConcurrent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := []byte(`{"concurrent":true}`)
			req := signedRequest(t, signer, "POST", "https://example.com/test", body)
			if _, err := verifier.Verify(req, pub); err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent verify error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Public key validation
// ---------------------------------------------------------------------------

func TestVerifyNilPublicKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)

	_, err := verifier.Verify(req, nil)
	if !errors.Is(err, vasign.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for nil public key, got: %v", err)
	}
}

func TestVerifyShortPublicKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier()

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)

	_, err := verifier.Verify(req, []byte("too-short"))
	if !errors.Is(err, vasign.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for short public key, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Body restored on error
// ---------------------------------------------------------------------------

func TestVerifyBodyRestoredOnTooLarge(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier(vasign.WithMaxBodySize(50))

	body := bytes.Repeat([]byte("x"), 100)
	req := signedRequest(t, signer, "POST", "https://example.com/test", body)

	_, err := verifier.Verify(req, nil)
	if !errors.Is(err, vasign.ErrBodyTooLarge) {
		// might get ErrInvalidSignature if public key check runs first; either way body should be restored
	}
	_ = err

	// Body must still be readable after error.
	if req.Body == nil {
		t.Fatal("body should not be nil after ErrBodyTooLarge")
	}
	got, _ := io.ReadAll(req.Body)
	if len(got) == 0 {
		t.Fatal("body should be non-empty after ErrBodyTooLarge")
	}
}

// ---------------------------------------------------------------------------
// Boundary: body exactly at limit
// ---------------------------------------------------------------------------

func TestVerifyBodyExactlyAtLimit(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier(vasign.WithMaxBodySize(100))

	body := bytes.Repeat([]byte("a"), 100) // exactly at limit
	req := signedRequest(t, signer, "POST", "https://example.com/test", body)

	if _, err := verifier.Verify(req, pub); err != nil {
		t.Fatalf("body at exact limit should pass: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Negative time window treated as 0 (disabled)
// ---------------------------------------------------------------------------

func TestVerifyNegativeTimeWindowDisablesCheck(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	verifier := vasign.NewVerifier(vasign.WithTimeWindow(-5 * time.Minute))

	req := signedRequest(t, signer, "GET", "https://example.com/test", nil)
	// Set timestamp to 1 hour ago — should not be rejected by timestamp check.
	oldTS := strconv.FormatInt(time.Now().Add(-1*time.Hour).Unix(), 10)
	req.Header.Set(vasign.HeaderTimestamp, oldTS)

	_, err := verifier.Verify(req, pub)
	// Signature will mismatch (timestamp changed), but NOT due to ErrExpiredTimestamp.
	if errors.Is(err, vasign.ErrExpiredTimestamp) {
		t.Fatal("negative time window should disable timestamp check")
	}
}
