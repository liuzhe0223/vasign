package vasign_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/liuzhe0223/vasign"
)

func ExampleNewTransport() {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("my-service", "key-1", priv)

	client := &http.Client{
		Transport: vasign.NewTransport(signer, nil),
	}

	// Every request made with this client is automatically signed.
	resp, err := client.Get("https://api.example.com/v1/accounts")
	if err != nil {
		// handle error
		return
	}
	defer resp.Body.Close()

	fmt.Println(resp.Status)
}

func ExampleSigner_Sign() {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := vasign.NewSigner("my-service", "key-1", priv)

	body := []byte(`{"amount":100}`)
	req, _ := http.NewRequest("POST", "https://api.example.com/v1/orders", bytes.NewReader(body))
	if err := signer.Sign(req); err != nil {
		// handle error
		return
	}

	// req now has X-Client-Id, X-Key-Id, X-Timestamp, X-Nonce, X-Signature headers.
	fmt.Println(req.Header.Get(vasign.HeaderClientID))
	// Output: my-service
}

func ExampleNewSignerFromBase64() {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privB64 := base64.StdEncoding.EncodeToString(priv)

	signer, err := vasign.NewSignerFromBase64("my-service", "key-1", privB64)
	if err != nil {
		// handle error
		return
	}

	fmt.Println(signer.PublicKeyBase64() != "")
	// Output: true
}
