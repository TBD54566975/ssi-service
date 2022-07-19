package keystore

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestGenerateServiceKey(t *testing.T) {
	emptySKPassword := ""
	_, _, err := GenerateServiceKey(emptySKPassword)
	assert.Error(t, err)

	skPassword := "test-password"
	key, salt, err := GenerateServiceKey(skPassword)
	assert.NoError(t, err)
	assert.NotEmpty(t, key)
	assert.NotEmpty(t, salt)
}

func TestEncryptDecryptKey(t *testing.T) {
	skPassword := "test-password"
	key, _, err := GenerateServiceKey(skPassword)
	assert.NoError(t, err)
	assert.NotEmpty(t, key)

	// generate another key type
	_, privKey, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	encoding := base64.StdEncoding
	decodedKey, err := encoding.DecodeString(key)
	assert.NoError(t, err)
	assert.NotEmpty(t, decodedKey)

	// encrypt the key using our service key
	encryptedKey, err := EncryptKey(decodedKey, privKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, encryptedKey)

	// decrypt the key using our service key
	decryptedKey, err := DecryptKey(decodedKey, encryptedKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, decryptedKey)
	assert.EqualValues(t, privKey, decryptedKey)
}
