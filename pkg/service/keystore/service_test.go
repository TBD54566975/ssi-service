package keystore

import (
	"context"
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			kt: crypto.SECP256k1,
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
			assert.NoError(t, err)
			assert.EqualValues(t, privKey, privKeyReconstructed)
		})
	}
}

func TestStoreAndGetKey(t *testing.T) {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	assert.NoError(t, file.Close())
	bolt, err := storage.NewStorage(storage.Bolt, name)
	assert.NoError(t, err)
	assert.NotEmpty(t, bolt)

	// remove the db file after the test
	t.Cleanup(func() {
		_ = bolt.Close()
		_ = os.Remove(bolt.URI())
	})

	keyStore, err := NewKeyStoreService(
		config.KeyStoreServiceConfig{
			BaseServiceConfig: &config.BaseServiceConfig{
				Name: "test-keyStore",
			},
			ServiceKeyPassword: "test-password",
		},
		bolt)
	assert.NoError(t, err)
	assert.NotEmpty(t, keyStore)

	// store the key
	_, privKey, err := crypto.GenerateEd25519Key()
	assert.NoError(t, err)
	err = keyStore.StoreKey(context.Background(), StoreKeyRequest{
		ID:               "test-id",
		Type:             crypto.Ed25519,
		Controller:       "test-controller",
		PrivateKeyBase58: base58.Encode(privKey),
	})
	assert.NoError(t, err)

	// get it back
	keyResponse, err := keyStore.GetKey(context.Background(), GetKeyRequest{ID: "test-id"})
	assert.NoError(t, err)
	assert.NotEmpty(t, keyResponse)
	assert.Equal(t, privKey, keyResponse.Key)

	// make sure can create a signer properly
	signer, err := crypto.NewJWTSigner("kid", keyResponse.Key)
	assert.NoError(t, err)
	assert.NotEmpty(t, signer)
}

func TestStoreAndGetKeyWithExistingKeystorage(t *testing.T) {

	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	assert.NoError(t, file.Close())
	bolt, err := storage.NewStorage(storage.Bolt, name)
	assert.NoError(t, err)
	assert.NotEmpty(t, bolt)

	// remove the db file after the test
	t.Cleanup(func() {
		_ = bolt.Close()
		_ = os.Remove(bolt.URI())
	})

	config := config.KeyStoreServiceConfig{
		BaseServiceConfig: &config.BaseServiceConfig{
			Name: "test-keyStore",
		},
		ServiceKeyPassword: "test-password",
	}

	serviceKey, serviceKeySalt, err := GenerateServiceKey(config.ServiceKeyPassword)

	// Next, instantiate the key storage
	keyStoreStorage, err := NewKeyStoreStorage(s, ServiceKey{
		Base58Key:  serviceKey,
		Base58Salt: serviceKeySalt,
	})

	keyStore, err := NewKeyStoreFromKeystoreStorage(
		config,
		keyStoreStorage,
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, keyStore)

	// store the key
	_, privKey, err := crypto.GenerateEd25519Key()
	assert.NoError(t, err)
	err = keyStore.StoreKey(context.Background(), StoreKeyRequest{
		ID:               "test-id",
		Type:             crypto.Ed25519,
		Controller:       "test-controller",
		PrivateKeyBase58: base58.Encode(privKey),
	})
	assert.NoError(t, err)

	// get it back
	keyResponse, err := keyStore.GetKey(context.Background(), GetKeyRequest{ID: "test-id"})
	assert.NoError(t, err)
	assert.NotEmpty(t, keyResponse)
	assert.Equal(t, privKey, keyResponse.Key)

	// make sure can create a signer properly
	signer, err := crypto.NewJWTSigner("kid", keyResponse.Key)
	assert.NoError(t, err)
	assert.NotEmpty(t, signer)
}
