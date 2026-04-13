package vasign_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/liuzhe0223/vasign"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestSigner(t *testing.T) (ed25519.PublicKey, *vasign.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := vasign.NewSigner("test-client", "key-1", priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return pub, s
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func verifySignature(t *testing.T, pub ed25519.PublicKey, req *http.Request, body []byte) {
	t.Helper()
	sigBytes, err := base64.StdEncoding.DecodeString(req.Header.Get(vasign.HeaderSignature))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	signingString := req.Method + "\n" +
		req.URL.EscapedPath() + "\n" +
		req.URL.RawQuery + "\n" +
		req.Header.Get(vasign.HeaderTimestamp) + "\n" +
		req.Header.Get(vasign.HeaderNonce) + "\n" +
		sha256Hex(body)
	if !ed25519.Verify(pub, []byte(signingString), sigBytes) {
		t.Fatal("signature verification failed")
	}
}

// ---------------------------------------------------------------------------
// NewSigner
// ---------------------------------------------------------------------------

func TestNewSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("valid", func(t *testing.T) {
		s, err := vasign.NewSigner("c", "k", priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s == nil {
			t.Fatal("expected non-nil signer")
		}
	})

	t.Run("empty_client_id", func(t *testing.T) {
		_, err := vasign.NewSigner("", "k", priv)
		if err == nil {
			t.Fatal("expected error for empty client_id")
		}
		if !strings.Contains(err.Error(), "client_id") {
			t.Fatalf("error should mention client_id: %v", err)
		}
	})

	t.Run("empty_key_id", func(t *testing.T) {
		_, err := vasign.NewSigner("c", "", priv)
		if err == nil {
			t.Fatal("expected error for empty key_id")
		}
		if !strings.Contains(err.Error(), "key_id") {
			t.Fatalf("error should mention key_id: %v", err)
		}
	})

	t.Run("wrong_key_size", func(t *testing.T) {
		_, err := vasign.NewSigner("c", "k", []byte("short"))
		if err == nil {
			t.Fatal("expected error for wrong key size")
		}
	})

	t.Run("seed_size_key_hints_at_from_seed", func(t *testing.T) {
		_, err := vasign.NewSigner("c", "k", priv.Seed())
		if err == nil {
			t.Fatal("expected error for 32-byte key")
		}
		if !strings.Contains(err.Error(), "NewSignerFromSeed") {
			t.Fatalf("expected hint about NewSignerFromSeed, got: %v", err)
		}
	})

	t.Run("nil_key", func(t *testing.T) {
		_, err := vasign.NewSigner("c", "k", nil)
		if err == nil {
			t.Fatal("expected error for nil key")
		}
	})
}

// ---------------------------------------------------------------------------
// NewSignerFromBase64
// ---------------------------------------------------------------------------

func TestNewSignerFromBase64(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("valid", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString(priv)
		s, err := vasign.NewSignerFromBase64("c", "k", encoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s == nil {
			t.Fatal("expected non-nil signer")
		}
	})

	t.Run("invalid_base64", func(t *testing.T) {
		_, err := vasign.NewSignerFromBase64("c", "k", "not-valid!!!")
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})

	t.Run("wrong_decoded_size", func(t *testing.T) {
		short := base64.StdEncoding.EncodeToString(make([]byte, 10))
		_, err := vasign.NewSignerFromBase64("c", "k", short)
		if err == nil {
			t.Fatal("expected error for wrong decoded size")
		}
	})
}

// ---------------------------------------------------------------------------
// NewSignerFromSeed
// ---------------------------------------------------------------------------

func TestNewSignerFromSeed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("valid", func(t *testing.T) {
		seedB64 := base64.StdEncoding.EncodeToString(priv.Seed())
		s, err := vasign.NewSignerFromSeed("c", "k", seedB64)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s == nil {
			t.Fatal("expected non-nil signer")
		}
	})

	t.Run("invalid_base64", func(t *testing.T) {
		_, err := vasign.NewSignerFromSeed("c", "k", "%%%invalid%%%")
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})

	t.Run("wrong_seed_size", func(t *testing.T) {
		short := base64.StdEncoding.EncodeToString(make([]byte, 16))
		_, err := vasign.NewSignerFromSeed("c", "k", short)
		if err == nil {
			t.Fatal("expected error for wrong seed size")
		}
	})
}

// ---------------------------------------------------------------------------
// Seed and full private key produce identical signatures
// ---------------------------------------------------------------------------

func TestSeedAndFullKeyProduceSamePublicKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	fromFull, _ := vasign.NewSigner("c", "k", priv)
	fromSeed, _ := vasign.NewSignerFromSeed("c", "k", base64.StdEncoding.EncodeToString(priv.Seed()))

	if fromFull.PublicKeyBase64() != fromSeed.PublicKeyBase64() {
		t.Fatal("public keys from full key and seed should match")
	}
}

// ---------------------------------------------------------------------------
// Sign — happy paths
// ---------------------------------------------------------------------------

func TestSignAddsAllHeaders(t *testing.T) {
	pub, signer := newTestSigner(t)

	body := []byte(`{"hello":"world"}`)
	req, _ := http.NewRequest("POST", "https://example.com/v1/orders?page=1", bytes.NewReader(body))
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	for _, h := range []string{vasign.HeaderClientID, vasign.HeaderKeyID, vasign.HeaderTimestamp, vasign.HeaderNonce, vasign.HeaderSignature} {
		if req.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}

	if req.Header.Get(vasign.HeaderClientID) != "test-client" {
		t.Errorf("client_id: got %s, want test-client", req.Header.Get(vasign.HeaderClientID))
	}
	if req.Header.Get(vasign.HeaderKeyID) != "key-1" {
		t.Errorf("key_id: got %s, want key-1", req.Header.Get(vasign.HeaderKeyID))
	}

	verifySignature(t, pub, req, body)
}

func TestSignEmptyBody(t *testing.T) {
	pub, signer := newTestSigner(t)

	req, _ := http.NewRequest("GET", "https://example.com/v1/accounts", nil)
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	verifySignature(t, pub, req, []byte{})
}

func TestSignBodyRemainsReadable(t *testing.T) {
	_, signer := newTestSigner(t)

	body := []byte(`{"data":true}`)
	req, _ := http.NewRequest("POST", "https://example.com/test", bytes.NewReader(body))
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	if buf.String() != string(body) {
		t.Fatalf("body after sign: got %q, want %q", buf.String(), string(body))
	}
}

func TestSignLargeBody(t *testing.T) {
	pub, signer := newTestSigner(t)

	body := bytes.Repeat([]byte("a"), 1<<20) // 1 MB
	req, _ := http.NewRequest("PUT", "https://example.com/upload", bytes.NewReader(body))
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	verifySignature(t, pub, req, body)

	// Body still readable.
	got, _ := io.ReadAll(req.Body)
	if !bytes.Equal(got, body) {
		t.Fatal("body mismatch after signing large body")
	}
}

func TestSignPercentEncodedPath(t *testing.T) {
	pub, signer := newTestSigner(t)

	req, _ := http.NewRequest("GET", "https://example.com/v1/users/hello%2Fworld", nil)
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Must use the escaped path in the signing string.
	sigBytes, _ := base64.StdEncoding.DecodeString(req.Header.Get(vasign.HeaderSignature))
	signingString := "GET\n/v1/users/hello%2Fworld\n\n" +
		req.Header.Get(vasign.HeaderTimestamp) + "\n" +
		req.Header.Get(vasign.HeaderNonce) + "\n" +
		sha256Hex([]byte{})
	if !ed25519.Verify(pub, []byte(signingString), sigBytes) {
		t.Fatal("signature verification failed for percent-encoded path")
	}
}

func TestSignSpaceInPath(t *testing.T) {
	pub, signer := newTestSigner(t)

	req, _ := http.NewRequest("GET", "https://example.com/v1/hello%20world", nil)
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	verifySignature(t, pub, req, []byte{})
}

func TestSignMultipleQueryParams(t *testing.T) {
	pub, signer := newTestSigner(t)

	req, _ := http.NewRequest("GET", "https://example.com/search?q=test&page=2&limit=10", nil)
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	verifySignature(t, pub, req, []byte{})
}

func TestSignEmptyPath(t *testing.T) {
	pub, signer := newTestSigner(t)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	verifySignature(t, pub, req, []byte{})
}

func TestSignDifferentHTTPMethods(t *testing.T) {
	pub, signer := newTestSigner(t)

	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			var bodyReader io.Reader
			var body []byte
			if method == "POST" || method == "PUT" || method == "PATCH" {
				body = []byte(`{"data":1}`)
				bodyReader = bytes.NewReader(body)
			}

			req, _ := http.NewRequest(method, "https://example.com/test", bodyReader)
			if err := signer.Sign(req); err != nil {
				t.Fatalf("sign %s: %v", method, err)
			}

			if body == nil {
				body = []byte{}
			}
			verifySignature(t, pub, req, body)
		})
	}
}

func TestSignNilHeader(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/test"},
	}
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign with nil header: %v", err)
	}
	if req.Header.Get(vasign.HeaderSignature) == "" {
		t.Fatal("expected signature header")
	}
}

func TestSignIdempotent(t *testing.T) {
	pub, signer := newTestSigner(t)

	// Signing the same request twice should produce valid signatures each time.
	body := []byte(`test`)
	req, _ := http.NewRequest("POST", "https://example.com/test", bytes.NewReader(body))
	if err := signer.Sign(req); err != nil {
		t.Fatalf("first sign: %v", err)
	}
	verifySignature(t, pub, req, body)
	firstSig := req.Header.Get(vasign.HeaderSignature)

	// Re-sign (body was replaced with a new reader by the first Sign).
	if err := signer.Sign(req); err != nil {
		t.Fatalf("second sign: %v", err)
	}
	verifySignature(t, pub, req, body)

	// Nonces should differ.
	secondSig := req.Header.Get(vasign.HeaderSignature)
	if firstSig == secondSig {
		t.Fatal("two signs produced identical signatures (nonce collision extremely unlikely)")
	}
}

func TestSignUnicodeQueryParam(t *testing.T) {
	pub, signer := newTestSigner(t)

	req, _ := http.NewRequest("GET", "https://example.com/search?q=%E4%BD%A0%E5%A5%BD", nil)
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	verifySignature(t, pub, req, []byte{})
}

// ---------------------------------------------------------------------------
// Sign — error paths
// ---------------------------------------------------------------------------

func TestSignRejectsNilURL(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	req := &http.Request{Method: "GET", Header: http.Header{}}
	if err := signer.Sign(req); err == nil {
		t.Fatal("expected error for nil URL")
	}
}

// errReader is a reader that always returns an error.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }
func (errReader) Close() error             { return nil }

func TestSignBodyReadError(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	req, _ := http.NewRequest("POST", "https://example.com/test", nil)
	req.Body = errReader{}

	err := signer.Sign(req)
	if err == nil {
		t.Fatal("expected error for body read failure")
	}
	if !strings.Contains(err.Error(), "read body") {
		t.Fatalf("error should mention read body: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Sign — concurrency
// ---------------------------------------------------------------------------

func TestSignConcurrent(t *testing.T) {
	pub, signer := newTestSigner(t)

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := []byte(`{"i":"concurrent"}`)
			req, _ := http.NewRequest("POST", "https://example.com/test?n=1", bytes.NewReader(body))
			if err := signer.Sign(req); err != nil {
				errs <- err
				return
			}

			sigBytes, _ := base64.StdEncoding.DecodeString(req.Header.Get(vasign.HeaderSignature))
			signingString := req.Method + "\n" +
				req.URL.EscapedPath() + "\n" +
				req.URL.RawQuery + "\n" +
				req.Header.Get(vasign.HeaderTimestamp) + "\n" +
				req.Header.Get(vasign.HeaderNonce) + "\n" +
				sha256Hex(body)
			if !ed25519.Verify(pub, []byte(signingString), sigBytes) {
				errs <- errors.New("signature verification failed")
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent sign error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Sign — nonce uniqueness
// ---------------------------------------------------------------------------

func TestSignNoncesAreUnique(t *testing.T) {
	_, signer := newTestSigner(t)

	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		req, _ := http.NewRequest("GET", "https://example.com/test", nil)
		if err := signer.Sign(req); err != nil {
			t.Fatalf("sign: %v", err)
		}
		nonce := req.Header.Get(vasign.HeaderNonce)
		if _, ok := seen[nonce]; ok {
			t.Fatalf("duplicate nonce after %d iterations: %s", i, nonce)
		}
		seen[nonce] = struct{}{}
	}
}

// ---------------------------------------------------------------------------
// PublicKey / PublicKeyBase64
// ---------------------------------------------------------------------------

func TestPublicKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	got := signer.PublicKey()
	if !bytes.Equal(got, pub) {
		t.Fatal("public key mismatch")
	}
}

func TestPublicKeyBase64(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	got := signer.PublicKeyBase64()
	want := base64.StdEncoding.EncodeToString(pub)
	if got != want {
		t.Fatalf("public key base64: got %s, want %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// Transport — happy paths
// ---------------------------------------------------------------------------

func TestTransportSignsRequests(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("t-client", "k-1", priv)

	var capturedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: vasign.NewTransport(signer, nil),
	}

	resp, err := client.Get(ts.URL + "/v1/test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if capturedReq.Header.Get(vasign.HeaderClientID) != "t-client" {
		t.Fatal("transport did not set client_id header")
	}

	sigBytes, _ := base64.StdEncoding.DecodeString(capturedReq.Header.Get(vasign.HeaderSignature))
	signingString := "GET\n/v1/test\n\n" +
		capturedReq.Header.Get(vasign.HeaderTimestamp) + "\n" +
		capturedReq.Header.Get(vasign.HeaderNonce) + "\n" +
		sha256Hex([]byte{})

	if !ed25519.Verify(pub, []byte(signingString), sigBytes) {
		t.Fatal("transport signature verification failed")
	}
}

func TestTransportWithPostBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	var capturedBody []byte
	var capturedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: vasign.NewTransport(signer, nil),
	}

	body := []byte(`{"amount":100}`)
	resp, err := client.Post(ts.URL+"/v1/orders", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if string(capturedBody) != string(body) {
		t.Fatalf("body: got %q, want %q", capturedBody, body)
	}

	sigBytes, _ := base64.StdEncoding.DecodeString(capturedReq.Header.Get(vasign.HeaderSignature))
	signingString := "POST\n/v1/orders\n\n" +
		capturedReq.Header.Get(vasign.HeaderTimestamp) + "\n" +
		capturedReq.Header.Get(vasign.HeaderNonce) + "\n" +
		sha256Hex(body)

	if !ed25519.Verify(pub, []byte(signingString), sigBytes) {
		t.Fatal("transport POST body signature verification failed")
	}
}

func TestTransportDoesNotMutateOriginalRequest(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: vasign.NewTransport(signer, nil),
	}

	req, _ := http.NewRequest("GET", ts.URL+"/test", nil)
	originalHeaders := req.Header.Clone()

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	for _, h := range []string{vasign.HeaderClientID, vasign.HeaderKeyID, vasign.HeaderTimestamp, vasign.HeaderNonce, vasign.HeaderSignature} {
		if req.Header.Get(h) != originalHeaders.Get(h) {
			t.Errorf("original request header %s was mutated", h)
		}
	}
}

func TestTransportWithCustomBase(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	called := false
	custom := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		// Verify the clone was signed before reaching us.
		if req.Header.Get(vasign.HeaderSignature) == "" {
			t.Fatal("request not signed before reaching custom transport")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})

	tr := vasign.NewTransport(signer, custom)
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	resp.Body.Close()
	if !called {
		t.Fatal("custom base transport was not called")
	}
}

// roundTripFunc adapts a function to the http.RoundTripper interface.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// ---------------------------------------------------------------------------
// Transport — error paths
// ---------------------------------------------------------------------------

func TestNewTransportPanicsOnNilSigner(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil signer")
		}
	}()
	vasign.NewTransport(nil, nil)
}

func TestTransportSignErrorPropagates(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)
	tr := vasign.NewTransport(signer, nil)

	// Construct a request with nil URL — Sign should fail.
	req := &http.Request{Method: "GET", Header: http.Header{}}
	_, err := tr.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error when sign fails in transport")
	}
}

func TestTransportBaseTransportError(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	failing := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})

	tr := vasign.NewTransport(signer, failing)
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	_, err := tr.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error from failing base transport")
	}
	if !strings.Contains(err.Error(), "network down") {
		t.Fatalf("expected base transport error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Transport — concurrency
// ---------------------------------------------------------------------------

func TestTransportConcurrent(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("c", "k", priv)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: vasign.NewTransport(signer, nil),
	}

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(ts.URL + "/test")
			if err != nil {
				errs <- err
				return
			}
			resp.Body.Close()
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent transport error: %v", err)
	}
}
