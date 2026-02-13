package wgkeys

import (
	"encoding/base64"
	"testing"
)

func TestGenerate(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Keys should not be zero.
	if kp.Private == (Key{}) {
		t.Fatal("private key is zero")
	}
	if kp.Public == (Key{}) {
		t.Fatal("public key is zero")
	}

	// Private and public must differ.
	if kp.Private == kp.Public {
		t.Fatal("private and public keys are identical")
	}
}

func TestClampPrivateKey(t *testing.T) {
	// Clamping rules:
	//   byte[0]  & 248  → bits 0,1,2 cleared
	//   byte[31] & 127  → bit 7 cleared
	//   byte[31] | 64   → bit 6 set

	k := Key{}
	// Set all bits to 0xFF to make clamping observable.
	for i := range k {
		k[i] = 0xFF
	}

	clampPrivateKey(&k)

	if k[0]&7 != 0 {
		t.Errorf("first byte low 3 bits not cleared: %08b", k[0])
	}
	if k[31]&128 != 0 {
		t.Errorf("last byte bit 7 not cleared: %08b", k[31])
	}
	if k[31]&64 == 0 {
		t.Errorf("last byte bit 6 not set: %08b", k[31])
	}
}

func TestDeterministicPublicKey(t *testing.T) {
	// Same private key should always produce the same public key.
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	pub2, err := publicFromPrivate(kp.Private)
	if err != nil {
		t.Fatalf("publicFromPrivate() error: %v", err)
	}
	if kp.Public != pub2 {
		t.Fatal("same private key produced different public keys")
	}
}

func TestKeyString(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	s := kp.Private.String()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(b) != KeyLen {
		t.Fatalf("decoded key length = %d, want %d", len(b), KeyLen)
	}
}

func TestParseKey(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	encoded := kp.Public.String()
	parsed, err := ParseKey(encoded)
	if err != nil {
		t.Fatalf("ParseKey() error: %v", err)
	}
	if parsed != kp.Public {
		t.Fatal("round-trip parse mismatch")
	}
}

func TestParseKeyInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"not base64", "!!!invalid!!!"},
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseKey(tt.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestUniqueKeys(t *testing.T) {
	// Two generated key pairs should differ.
	kp1, _ := Generate()
	kp2, _ := Generate()

	if kp1.Private == kp2.Private {
		t.Fatal("two generated private keys are identical")
	}
	if kp1.Public == kp2.Public {
		t.Fatal("two generated public keys are identical")
	}
}
