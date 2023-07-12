package keystore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/benbjohnson/clock"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestGenerateServiceKey(t *testing.T) {
	key, err := GenerateServiceKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, key)
}

func TestEncryptDecryptAllKeyTypes(t *testing.T) {
	serviceKeyEncoded, err := GenerateServiceKey()
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
	keyStore, err := createKeyStoreService(t)
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
	signer, err := jwx.NewJWXSigner("test-id", "kid", keyResponse.Key)
	assert.NoError(t, err)
	assert.NotEmpty(t, signer)
}

func TestRevokeKey(t *testing.T) {
	keyStore, err := createKeyStoreService(t)
	assert.NoError(t, err)
	assert.NotEmpty(t, keyStore)

	// store the key
	_, privKey, err := crypto.GenerateEd25519Key()
	assert.NoError(t, err)
	keyID := "test-revocation-id"
	err = keyStore.StoreKey(context.Background(), StoreKeyRequest{
		ID:               keyID,
		Type:             crypto.Ed25519,
		Controller:       "test-revocation-controller",
		PrivateKeyBase58: base58.Encode(privKey),
	})
	assert.NoError(t, err)

	// get it back
	keyResponse, err := keyStore.GetKey(context.Background(), GetKeyRequest{ID: keyID})
	assert.NoError(t, err)
	assert.NotEmpty(t, keyResponse)
	assert.Equal(t, privKey, keyResponse.Key)
	assert.False(t, keyResponse.Revoked)
	assert.Empty(t, keyResponse.RevokedAt)

	// revoke the key
	err = keyStore.RevokeKey(context.Background(), RevokeKeyRequest{ID: keyID})
	assert.NoError(t, err)

	// get the key after revocation
	keyResponse, err = keyStore.GetKey(context.Background(), GetKeyRequest{ID: keyID})
	assert.NoError(t, err)
	assert.NotEmpty(t, keyResponse)
	assert.Equal(t, privKey, keyResponse.Key)
	assert.True(t, keyResponse.Revoked)
	assert.Equal(t, "2023-06-23T00:00:00Z", keyResponse.RevokedAt)

	// attempt to "Sign()" with the revoked key, ensure it is prohibited
	_, err = keyStore.Sign(context.Background(), keyID, "sampleDataAsString")
	assert.Error(t, err)
	assert.ErrorContains(t, err, "cannot use revoked key")
}

func createKeyStoreService(t *testing.T) (*Service, error) {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	assert.NoError(t, file.Close())
	s, err := storage.NewStorage(storage.Bolt, storage.Option{
		ID:     storage.BoltDBFilePathOption,
		Option: name,
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, s)

	// remove the db file after the test
	t.Cleanup(func() {
		_ = s.Close()
		_ = os.Remove(s.URI())
	})

	keyStore, err := NewKeyStoreService(
		config.KeyStoreServiceConfig{
			BaseServiceConfig: &config.BaseServiceConfig{
				Name: "test-keyStore",
			},
		},
		s)

	mockClock := clock.NewMock()
	mockClock.Set(time.Date(2023, 06, 23, 0, 0, 0, 0, time.UTC))
	keyStore.storage.Clock = mockClock

	return keyStore, err
}
