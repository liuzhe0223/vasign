// Command keygen generates an Ed25519 key pair for vasign API authentication.
//
// Usage:
//
//	go run github.com/liuzhe0223/vasign/cmd/keygen
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	fmt.Println("=== Ed25519 Key Pair ===")
	fmt.Println()
	fmt.Println("Private Key (base64, 64 bytes — keep secret):")
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
	fmt.Println()
	fmt.Println("Seed (base64, 32 bytes — alternative compact format):")
	fmt.Println(base64.StdEncoding.EncodeToString(priv.Seed()))
	fmt.Println()
	fmt.Println("Public Key (base64, 32 bytes — register with your API server):")
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
}
