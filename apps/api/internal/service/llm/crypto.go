package llm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext using AES-256-GCM with the given 32-byte key.
//
// The returned ciphertext is (nonce || sealed). Callers may base64-encode
// the result before persisting to DB / .env. Use Decrypt to reverse.
//
// SECURITY: key MUST be exactly 32 bytes. The caller is expected to source
// the key from config.Config.GetEncryptionKey() (env ENCRYPTION_KEY, enforced
// at startup by validateEncryptionKey in cmd/server/main.go — Trust Rescue
// 9.2.3). This package does not read the env directly to keep the helper
// dependency-free and unit-testable.
//
// Note: LLM_PROVIDER_DESIGN.md §7.1 names the master key
// "SBOMHUB_ENCRYPTION_KEY" but the existing codebase / Trust Rescue 9.2.3
// uses ENCRYPTION_KEY. We accept any 32-byte key here and let the caller
// resolve the env naming. // ※要確認: doc / impl env name mismatch.
func Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("llm/crypto: key must be exactly 32 bytes (got %d)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("llm/crypto: aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("llm/crypto: cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("llm/crypto: nonce generation: %w", err)
	}

	// gcm.Seal prepends nothing — we explicitly prepend the nonce so the
	// ciphertext is self-contained.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. ciphertext must be the (nonce || sealed) blob
// produced by Encrypt with the same 32-byte key.
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("llm/crypto: key must be exactly 32 bytes (got %d)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("llm/crypto: aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("llm/crypto: cipher.NewGCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("llm/crypto: ciphertext too short (need >= %d bytes, got %d)", nonceSize, len(ciphertext))
	}

	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		// SECURITY: never wrap with the ciphertext or key in scope — only
		// return a generic auth-failure-ish error.
		return nil, fmt.Errorf("llm/crypto: gcm.Open: %w", err)
	}
	return plaintext, nil
}
