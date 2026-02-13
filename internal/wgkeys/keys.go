// Package wgkeys generates WireGuard Curve25519 key pairs in pure Go.
//
// WireGuard keys are 32-byte Curve25519 keys. A private key is generated
// from random bytes with clamping (clear bits 0,1,2 of first byte, set
// bit 6 of last byte, clear bit 7 of last byte). The public key is the
// Curve25519 scalar base multiplication of the private key.
package wgkeys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const KeyLen = 32

// Key is a 32-byte WireGuard key (private or public).
type Key [KeyLen]byte

// KeyPair holds a WireGuard private/public key pair.
type KeyPair struct {
	Private Key
	Public  Key
}

// Generate creates a new WireGuard key pair.
// It reads 32 random bytes, applies Curve25519 clamping, then derives the public key.
func Generate() (KeyPair, error) {
	var private Key

	if _, err := rand.Read(private[:]); err != nil {
		return KeyPair{}, fmt.Errorf("reading random bytes: %w", err)
	}

	clampPrivateKey(&private)

	public, err := publicFromPrivate(private)
	if err != nil {
		return KeyPair{}, fmt.Errorf("deriving public key: %w", err)
	}

	return KeyPair{Private: private, Public: public}, nil
}

// clampPrivateKey applies WireGuard's Curve25519 clamping to a private key.
// This matches the clamping in WireGuard's key generation.
func clampPrivateKey(k *Key) {
	k[0] &= 248  // Clear bits 0, 1, 2
	k[31] &= 127 // Clear bit 7
	k[31] |= 64  // Set bit 6
}

// publicFromPrivate computes the Curve25519 public key from a (clamped) private key.
func publicFromPrivate(private Key) (Key, error) {
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return Key{}, err
	}
	var public Key
	copy(public[:], pub)
	return public, nil
}

// String returns the base64-encoded representation (WireGuard standard format).
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// ParseKey decodes a base64 WireGuard key string into a Key.
func ParseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("decoding base64: %w", err)
	}
	if len(b) != KeyLen {
		return Key{}, fmt.Errorf("invalid key length: got %d, want %d", len(b), KeyLen)
	}
	var k Key
	copy(k[:], b)
	return k, nil
}
