package llm

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func newTestKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return key
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key := newTestKey(t)
	for _, plaintext := range []string{
		"",
		"sk-test-1234567890",
		"日本語の API キー (placeholder)",
		strings.Repeat("A", 4096),
	} {
		ct, err := Encrypt([]byte(plaintext), key)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plaintext, err)
		}
		pt, err := Decrypt(ct, key)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(pt) != plaintext {
			t.Errorf("roundtrip mismatch: got %q, want %q", pt, plaintext)
		}
	}
}

func TestEncrypt_NonceIsRandom(t *testing.T) {
	key := newTestKey(t)
	plaintext := []byte("same input twice")

	ct1, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt #1: %v", err)
	}
	ct2, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt #2: %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of identical plaintext produced identical ciphertext (nonce reused?)")
	}
}

func TestEncrypt_WrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, 24, 31, 33, 64} {
		key := make([]byte, n)
		_, err := Encrypt([]byte("x"), key)
		if err == nil {
			t.Errorf("Encrypt(key len=%d) should fail", n)
		}
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := newTestKey(t)
	key2 := newTestKey(t)

	ct, err := Encrypt([]byte("secret"), key1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(ct, key2); err == nil {
		t.Error("Decrypt with wrong key should fail (authentication tag mismatch)")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	key := newTestKey(t)
	if _, err := Decrypt([]byte{1, 2, 3}, key); err == nil {
		t.Error("Decrypt of too-short ciphertext should fail")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := newTestKey(t)
	ct, err := Encrypt([]byte("secret"), key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Flip a bit in the sealed body (not the nonce, to make the test
	// deterministic — flipping nonce bits also fails, but via Open's
	// auth check).
	ct[len(ct)-1] ^= 0x01
	if _, err := Decrypt(ct, key); err == nil {
		t.Error("Decrypt of tampered ciphertext should fail (GCM auth tag)")
	}
}
