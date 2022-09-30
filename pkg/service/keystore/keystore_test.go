package keystore

import (
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/storage"
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

func TestEncryptDecryptAllKeyTypes(t *testing.T) {
	skPassword := "test-password"
	serviceKeyEncoded, _, err := GenerateServiceKey(skPassword)
	assert.NoError(t, err)
	serviceKey, err := base58.Decode(serviceKeyEncoded)
	assert.NoError(t, err)
	assert.NotEmpty(t, serviceKey)

	tests := []struct {
		kt crypto.KeyType
	}{
		{
			kt: crypto.Ed25519,
		},
		{
			kt: crypto.X25519,
		},
		{
			kt: crypto.Secp256k1,
		},
		{
			kt: crypto.P224,
		},
		{
			kt: crypto.P256,
		},
		{
			kt: crypto.P384,
		},
		{
			kt: crypto.P521,
		},
		{
			kt: crypto.RSA,
		},
	}
	for _, test := range tests {
		t.Run(string(test.kt), func(t *testing.T) {
			// generate a new key based on the given key type
			_, privKey, err := crypto.GenerateKeyByKeyType(test.kt)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKey)

			// serialize the key before encryption
			privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKeyBytes)

			// encrypt the serviceKey using our service serviceKey
			encryptedKey, err := EncryptKey(serviceKey, privKeyBytes)
			assert.NoError(t, err)
			assert.NotEmpty(t, encryptedKey)

			// decrypt the serviceKey using our service serviceKey
			decryptedKey, err := DecryptKey(serviceKey, encryptedKey)
			assert.NoError(t, err)
			assert.NotEmpty(t, decryptedKey)

			// reconstruct the key from its serialized form
			privKeyReconstructed, err := crypto.BytesToPrivKey(decryptedKey, test.kt)
			assert.EqualValues(t, privKey, privKeyReconstructed)
		})
	}
}

func TestStoreAndGetKey(t *testing.T) {
	bolt, err := storage.NewBoltDB()
	assert.NoError(t, err)
	assert.NotEmpty(t, bolt)
	// remove the db file after the test
	t.Cleanup(func() {
		_ = bolt.Close()
		_ = os.Remove(storage.DBFile)
	})

	storage, err := NewKeyStoreService(
		config.KeyStoreServiceConfig{
			BaseServiceConfig: &config.BaseServiceConfig{
				Name: "test-keystore",
			},
			ServiceKeyPassword: "test-password",
		},
		bolt)
	assert.NoError(t, err)
	assert.NotEmpty(t, storage)

	// store the key
	_, privKey, err := crypto.GenerateEd25519Key()
	err = storage.StoreKey(StoreKeyRequest{
		ID:         "test-id",
		Type:       crypto.Ed25519,
		Controller: "test-controller",
		Key:        privKey,
	})
	assert.NoError(t, err)

	// get it back
	keyResponse, err := storage.GetKey(GetKeyRequest{ID: "test-id"})
	assert.NoError(t, err)
	assert.NotEmpty(t, keyResponse)

	assert.EqualValues(t, privKey, keyResponse.Key)
}
