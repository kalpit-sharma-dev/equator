package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// pkcs5Pad applies PKCS5 padding to the input data using the given block size.
//
// Go's stdlib does not expose a named PKCS5 helper, so it is implemented here.
// With AES's 16-byte block size, PKCS5 is byte-for-byte identical to PKCS7
// and is therefore wire-compatible with Java's "AES/CBC/PKCS5Padding".
func pkcs5Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs5Unpad removes PKCS5 padding from the input data. It validates every
// padding byte to detect tampering or a wrong key.
func pkcs5Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[length-1])
	if padding < 1 || padding > blockSize {
		return nil, fmt.Errorf("invalid padding size: %d", padding)
	}
	if length < padding {
		return nil, fmt.Errorf("data shorter than padding")
	}
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return data[:length-padding], nil
}

// minBase64IVChars is the smallest legal length of a Base64-encoded
// IV-only payload (16 raw bytes -> 24 Base64 chars including padding).
// A real ciphertext will always be longer, but any input shorter than this
// cannot possibly be a valid encrypted blob.
const minBase64IVChars = 24

// Encrypt performs AES-256-CBC encryption with PKCS5 padding.
//
// Steps:
//  1. Generate a random 16-byte IV using crypto/rand.
//  2. AES-256-CBC encrypt the PKCS5-padded plaintext.
//  3. Prepend IV to the ciphertext: result = IV || ciphertext.
//  4. Base64 encode the combined buffer.
//
// The same plaintext encrypts to a different ciphertext each call because the
// IV is random. This is intentional and matches the design.
func Encrypt(key []byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", fmt.Errorf("plaintext is empty")
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	padded := pkcs5Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	result := make([]byte, 0, len(iv)+len(ciphertext))
	result = append(result, iv...)
	result = append(result, ciphertext...)
	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt reverses Encrypt. Input is Base64(IV || ciphertext).
//
// Steps:
//  1. Cheap length sanity check on the Base64 string.
//  2. Base64 decode.
//  3. Split first 16 bytes as IV, remainder as ciphertext.
//  4. AES-256-CBC decrypt into a SEPARATE destination slice.
//  5. Remove PKCS5 padding.
//
// CBC IN-PLACE SAFETY:
// We deliberately decrypt into a freshly-allocated `plaintext` slice rather
// than reusing the `raw` buffer (or the `ciphertext` sub-slice of it).
// Decrypting in-place — i.e. `mode.CryptBlocks(raw[aes.BlockSize:], raw[aes.BlockSize:])` —
// is technically allowed by crypto/cipher, but it has bitten teams in the past
// because the same underlying memory is read and written in the same call.
// Allocating a separate destination is cheap, removes the foot-gun, and keeps
// the code obviously correct under review.
func Decrypt(key []byte, ciphertextB64 string) (string, error) {
	if len(ciphertextB64) < minBase64IVChars {
		return "", fmt.Errorf("ciphertext too short: need at least %d base64 chars (16-byte IV), got %d", minBase64IVChars, len(ciphertextB64))
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}
	if len(raw) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := raw[:aes.BlockSize]
	ciphertext := raw[aes.BlockSize:]
	if len(ciphertext) == 0 {
		return "", fmt.Errorf("ciphertext is empty after IV")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	// Allocate a separate destination slice — see "CBC IN-PLACE SAFETY" above.
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	unpadded, err := pkcs5Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("pkcs5 unpad failed (wrong key or corrupt data): %w", err)
	}
	return string(unpadded), nil
}

// HashSHA256 returns the lowercase hex SHA-256 digest of value.
// Used to compute marker_id = SHA256(customer_id) for BigQuery lookups.
func HashSHA256(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
