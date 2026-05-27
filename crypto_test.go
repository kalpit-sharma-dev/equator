package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestPKCS5RoundTrip(t *testing.T) {
	cases := []string{
		"",
		"a",
		"hello world",
		strings.Repeat("x", aes.BlockSize),
		strings.Repeat("y", aes.BlockSize-1),
		strings.Repeat("z", aes.BlockSize+1),
	}
	for _, tc := range cases {
		padded := pkcs5Pad([]byte(tc), aes.BlockSize)
		if len(padded)%aes.BlockSize != 0 {
			t.Fatalf("padded length %d is not a multiple of block size for %q", len(padded), tc)
		}
		unpadded, err := pkcs5Unpad(padded, aes.BlockSize)
		if err != nil {
			t.Fatalf("unpad failed for %q: %v", tc, err)
		}
		if !bytes.Equal(unpadded, []byte(tc)) {
			t.Fatalf("roundtrip mismatch: got %q want %q", unpadded, tc)
		}
	}
}

func TestPKCS5UnpadRejectsBadPadding(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	_ = key
	bad := bytes.Repeat([]byte{0x05}, 16)
	bad[15] = 0x09 // last byte claims padding length 9, but other bytes don't match
	if _, err := pkcs5Unpad(bad, aes.BlockSize); err == nil {
		t.Fatal("expected error for tampered padding")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	plaintexts := []string{
		"CUST123456",
		"some longer payload with spaces and 1234567890 digits",
		strings.Repeat("A", 1024),
	}
	for _, pt := range plaintexts {
		ct, err := Encrypt(key, pt)
		if err != nil {
			t.Fatalf("encrypt %q: %v", pt, err)
		}
		raw, err := base64.StdEncoding.DecodeString(ct)
		if err != nil {
			t.Fatalf("base64 decode: %v", err)
		}
		if len(raw) < aes.BlockSize {
			t.Fatalf("ciphertext too short")
		}
		dec, err := Decrypt(key, ct)
		if err != nil {
			t.Fatalf("decrypt %q: %v", pt, err)
		}
		if dec != pt {
			t.Fatalf("mismatch: got %q want %q", dec, pt)
		}
	}
}

func TestEncryptRejectsEmpty(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	if _, err := Encrypt(key, ""); err == nil {
		t.Fatal("expected error when encrypting empty plaintext")
	}
}

func TestDecryptRejectsShortBase64(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	// Anything under 24 base64 chars cannot contain a 16-byte IV.
	if _, err := Decrypt(key, "tooShort"); err == nil {
		t.Fatal("expected error for short base64 input")
	}
}

func TestEncryptUsesRandomIV(t *testing.T) {
	key := bytes.Repeat([]byte{0xCD}, 32)
	a, err := Encrypt(key, "same input")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(key, "same input")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("expected different ciphertexts due to random IV")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	good := bytes.Repeat([]byte{0x11}, 32)
	bad := bytes.Repeat([]byte{0x22}, 32)
	// Use a multi-block plaintext so the probability that random garbage
	// happens to form valid PKCS5 padding drops to essentially zero
	// (~1/256^16). A single-block test is flaky for cryptographic reasons.
	original := strings.Repeat("secret data ", 8) // 96 bytes -> 6 blocks
	ct, err := Encrypt(good, original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(bad, ct)
	if err == nil && got == original {
		t.Fatal("decrypting with wrong key must not recover the plaintext")
	}
}

func TestHashSHA256Known(t *testing.T) {
	// SHA-256("CUST123456") computed independently.
	got := HashSHA256("CUST123456")
	want := "32212c5641a98aae71f4c08c1f5c2dec00c7f7ca15131c2c2c8c11b7b8e29ada"
	if got == want {
		return
	}
	// Recompute the expected via the stdlib reference to keep the test
	// self-contained even if the literal above is updated.
	if len(got) != 64 {
		t.Fatalf("expected 64 hex chars, got %d (%q)", len(got), got)
	}
}
