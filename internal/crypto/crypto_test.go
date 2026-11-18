package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestLoadMasterKeyFromEnv(t *testing.T) {
	t.Run("missing key", func(t *testing.T) {
		t.Setenv(MasterKeyEnvVar, "")
		_, err := LoadMasterKeyFromEnv()
		if !errors.Is(err, ErrMissingMasterKey) {
			t.Fatalf("expected ErrMissingMasterKey, got %v", err)
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		t.Setenv(MasterKeyEnvVar, "short-key")
		_, err := LoadMasterKeyFromEnv()
		if !errors.Is(err, ErrInvalidMasterKey) {
			t.Fatalf("expected ErrInvalidMasterKey, got %v", err)
		}
	})

	t.Run("invalid 64-char non-hex", func(t *testing.T) {
		t.Setenv(MasterKeyEnvVar, strings.Repeat("z", 64))
		_, err := LoadMasterKeyFromEnv()
		if !errors.Is(err, ErrInvalidMasterKey) {
			t.Fatalf("expected ErrInvalidMasterKey, got %v", err)
		}
	})

	t.Run("32-byte raw string", func(t *testing.T) {
		rawKey := "0123456789abcdef0123456789abcdef" // 32 bytes
		t.Setenv(MasterKeyEnvVar, rawKey)

		c, err := LoadMasterKeyFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		ct, nonce, err := c.EncryptString("super-secret")
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		pt, err := c.DecryptString(ct, nonce)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if pt != "super-secret" {
			t.Fatalf("got %q, want %q", pt, "super-secret")
		}
	})

	t.Run("64-char hex string", func(t *testing.T) {
		rawBytes := bytes.Repeat([]byte{0xab}, 32)
		hexKey := hex.EncodeToString(rawBytes)
		t.Setenv(MasterKeyEnvVar, hexKey)

		c, err := LoadMasterKeyFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Cipher constructed directly from rawBytes must decrypt ciphertext produced via hexKey.
		c2, err := NewCipher(rawBytes)
		if err != nil {
			t.Fatalf("NewCipher failed: %v", err)
		}

		ct, nonce, err := c.Encrypt([]byte("db-password"))
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		pt, err := c2.Decrypt(ct, nonce)
		if err != nil {
			t.Fatalf("decrypt with c2 failed: %v", err)
		}
		if string(pt) != "db-password" {
			t.Fatalf("got %q, want %q", pt, "db-password")
		}
	})
}

func TestEncryptDecryptAndNonceUniqueness(t *testing.T) {
	c, err := NewCipherFromMasterKey("12345678901234567890123456789012")
	if err != nil {
		t.Fatalf("NewCipherFromMasterKey failed: %v", err)
	}

	ct1, n1, err := c.EncryptString("same-value")
	if err != nil {
		t.Fatalf("encrypt 1 failed: %v", err)
	}
	ct2, n2, err := c.EncryptString("same-value")
	if err != nil {
		t.Fatalf("encrypt 2 failed: %v", err)
	}

	if len(n1) != NonceSize || len(n2) != NonceSize {
		t.Fatalf("expected %d-byte nonce, got %d and %d", NonceSize, len(n1), len(n2))
	}
	if bytes.Equal(n1, n2) {
		t.Fatal("expected unique nonces across encryptions")
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatal("expected different ciphertexts for unique nonces")
	}

	// Tampered ciphertext must fail authentication.
	tampered := append([]byte(nil), ct1...)
	tampered[0] ^= 0xff
	if _, err := c.Decrypt(tampered, n1); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed for tampered ciphertext, got %v", err)
	}

	// Invalid nonce length must fail.
	if _, err := c.Decrypt(ct1, []byte("short")); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("expected ErrInvalidNonce, got %v", err)
	}

	// Stringer redaction check.
	if got := fmt.Sprintf("%s %#v", c, c); strings.Contains(got, "123456") {
		t.Fatalf("cipher leaked sensitive data in String/GoString: %s", got)
	}
}

func TestWebhookHMAC(t *testing.T) {
	secret := "whsec_test_secret"
	payload := []byte(`{"event":"secret.expiring","key":"STRIPE_API_KEY"}`)

	sig := SignWebhook(secret, payload)
	if len(sig) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(sig))
	}

	if !VerifyWebhookSignature(secret, payload, sig) {
		t.Fatal("expected valid raw hex signature to verify")
	}
	if !VerifyWebhookSignature(secret, payload, "sha256="+sig) {
		t.Fatal("expected valid prefixed signature to verify")
	}
	if VerifyWebhookSignature("wrong-secret", payload, sig) {
		t.Fatal("expected wrong secret to fail verification")
	}
	if VerifyWebhookSignature(secret, []byte(`{"tampered":true}`), sig) {
		t.Fatal("expected tampered payload to fail verification")
	}
	if VerifyWebhookSignature(secret, payload, "not-hex") {
		t.Fatal("expected malformed signature to fail verification")
	}
}

func TestTokenHash(t *testing.T) {
	token := "mkv_live_abc123xyz"
	hash := HashToken(token)

	if len(hash) != 64 {
		t.Fatalf("expected 64-char SHA-256 hex digest, got %d", len(hash))
	}
	if hash == token {
		t.Fatal("token hash must not equal raw token")
	}
	if !VerifyTokenHash(token, hash) {
		t.Fatal("expected token hash to verify")
	}
	if VerifyTokenHash("mkv_live_wrong", hash) {
		t.Fatal("expected wrong token to fail verification")
	}
	if VerifyTokenHash(token, "bad-hash") {
		t.Fatal("expected invalid hex hash to fail verification")
	}
}
