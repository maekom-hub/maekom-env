package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// MasterKeyEnvVar is the environment variable name used to load the master key.
	MasterKeyEnvVar = "MASTER_KEY"

	// MasterKeySize is the required AES-256 key size in bytes.
	MasterKeySize = 32

	// NonceSize is the standard 12-byte GCM nonce size.
	NonceSize = 12
)

var (
	// ErrMissingMasterKey is returned when MASTER_KEY is empty or unset.
	ErrMissingMasterKey = errors.New("crypto: MASTER_KEY environment variable is not set")

	// ErrInvalidMasterKey is returned when MASTER_KEY is neither a 32-byte raw string nor a 64-char hex string.
	ErrInvalidMasterKey = errors.New("crypto: MASTER_KEY must be a 32-byte raw string or 64-character hex string")

	// ErrInvalidNonce is returned when a nonce does not match NonceSize.
	ErrInvalidNonce = errors.New("crypto: invalid nonce length")

	// ErrDecryptionFailed is returned when AES-GCM authentication or decryption fails.
	ErrDecryptionFailed = errors.New("crypto: decryption failed")
)

// Cipher provides in-memory AES-256-GCM encryption and decryption using the master key.
// The master key is never persisted or serialized.
type Cipher struct {
	aead cipher.AEAD
}

// String prevents accidental logging of internal state.
func (c *Cipher) String() string {
	return "Cipher{redacted}"
}

// GoString prevents accidental fmt %#v logging of internal state.
func (c *Cipher) GoString() string {
	return "Cipher{redacted}"
}

// LoadMasterKeyFromEnv reads MASTER_KEY from the process environment into memory
// and constructs an AES-256-GCM Cipher.
func LoadMasterKeyFromEnv() (*Cipher, error) {
	return NewCipherFromMasterKey(os.Getenv(MasterKeyEnvVar))
}

// NewCipherFromMasterKey parses a 32-byte raw string or 64-character hex string
// and returns an AES-256-GCM Cipher.
func NewCipherFromMasterKey(raw string) (*Cipher, error) {
	key, err := ParseMasterKey(raw)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	return NewCipher(key)
}

// ParseMasterKey decodes a master key from either a 64-character hex string
// (representing 32 bytes) or a 32-byte raw string.
func ParseMasterKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, ErrMissingMasterKey
	}

	if len(raw) == MasterKeySize*2 {
		decoded, err := hex.DecodeString(raw)
		if err != nil || len(decoded) != MasterKeySize {
			return nil, ErrInvalidMasterKey
		}
		return decoded, nil
	}

	if len(raw) == MasterKeySize {
		key := make([]byte, MasterKeySize)
		copy(key, raw)
		return key, nil
	}

	return nil, ErrInvalidMasterKey
}

// NewCipher creates an AES-256-GCM Cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != MasterKeySize {
		return nil, ErrInvalidMasterKey
	}

	keyCopy := make([]byte, MasterKeySize)
	copy(keyCopy, key)
	defer clear(keyCopy)

	block, err := aes.NewCipher(keyCopy)
	if err != nil {
		return nil, fmt.Errorf("crypto: create aes cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: create gcm: %w", err)
	}
	if aead.NonceSize() != NonceSize {
		return nil, fmt.Errorf("crypto: unexpected gcm nonce size %d", aead.NonceSize())
	}

	return &Cipher{aead: aead}, nil
}

// Encrypt encrypts plaintext with AES-256-GCM and a fresh 12-byte random nonce.
func (c *Cipher) Encrypt(plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	if c == nil || c.aead == nil {
		return nil, nil, errors.New("crypto: cipher is not initialized")
	}

	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}

	ciphertext = c.aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// EncryptString encrypts a string secret with AES-256-GCM and a fresh 12-byte random nonce.
func (c *Cipher) EncryptString(plaintext string) (ciphertext []byte, nonce []byte, err error) {
	return c.Encrypt([]byte(plaintext))
}

// Decrypt decrypts AES-256-GCM ciphertext using the provided 12-byte nonce.
func (c *Cipher) Decrypt(ciphertext, nonce []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("crypto: cipher is not initialized")
	}
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonce
	}

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// DecryptString decrypts AES-256-GCM ciphertext into a string using the provided 12-byte nonce.
func (c *Cipher) DecryptString(ciphertext, nonce []byte) (string, error) {
	plaintext, err := c.Decrypt(ciphertext, nonce)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// SignWebhook generates a lowercase hex-encoded HMAC-SHA256 signature for a webhook payload.
func SignWebhook(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature verifies a hex-encoded HMAC-SHA256 webhook signature (with optional "sha256=" prefix)
// using constant-time comparison.
func VerifyWebhookSignature(secret string, payload []byte, signature string) bool {
	trimmed := strings.TrimPrefix(strings.TrimSpace(signature), "sha256=")
	got, err := hex.DecodeString(trimmed)
	if err != nil || len(got) != sha256.Size {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)

	return hmac.Equal(got, expected)
}

// HashToken returns the lowercase hex-encoded SHA-256 digest of a service token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// VerifyTokenHash verifies a raw service token against a stored hex-encoded SHA-256 hash
// using constant-time comparison.
func VerifyTokenHash(token, expectedHash string) bool {
	expected, err := hex.DecodeString(strings.TrimSpace(expectedHash))
	if err != nil || len(expected) != sha256.Size {
		return false
	}

	sum := sha256.Sum256([]byte(token))
	return hmac.Equal(sum[:], expected)
}
