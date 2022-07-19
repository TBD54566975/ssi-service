package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestArgon2(t *testing.T) {
	password := "test-password"
	salt, err := GenerateSalt(Argon2SaltSize)
	assert.NoError(t, err)
	assert.NotEmpty(t, salt)

	hash, err := Argon2KeyGen(password, salt, 32)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	hash2, err := Argon2KeyGen(password, salt, 32)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash2)

	assert.Equal(t, hash, hash2)
}

func TestXChaCha20Poly1305(t *testing.T) {
	// Generate a key
	password := "test-password"
	salt, err := GenerateSalt(Argon2SaltSize)
	assert.NoError(t, err)
	assert.NotEmpty(t, salt)

	key, err := Argon2KeyGen(password, salt, chacha20poly1305.KeySize)
	assert.NoError(t, err)
	assert.NotEmpty(t, key)

	// Encrypt a message
	message := []byte("open sesame")
	encrypted, err := XChaCha20Poly1305Encrypt(key, message)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Decrypt the message
	decrypted, err := XChaCha20Poly1305Decrypt(key, encrypted)
	assert.NoError(t, err)
	assert.Equal(t, message, decrypted)
}
