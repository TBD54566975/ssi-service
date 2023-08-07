package encryption

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/tbd54566975/ssi-service/internal/util"
)

func createServiceKey() (key string, err error) {
	keyBytes, err := util.GenerateSalt(chacha20poly1305.KeySize)
	if err != nil {
		err = errors.Wrap(err, "generating bytes for service key")
		return "", sdkutil.LoggingError(err)
	}

	key = base58.Encode(keyBytes)
	return
}

func TestEncryptDecryptAllKeyTypes(t *testing.T) {
	serviceKeyEncoded, err := createServiceKey()
	assert.NoError(t, err)
	serviceKey, err := base58.Decode(serviceKeyEncoded)
	assert.NoError(t, err)
	assert.NotEmpty(t, serviceKey)
	encrypter := NewXChaCha20Poly1305EncrypterWithKeyResolver(func(ctx context.Context) ([]byte, error) {
		return serviceKey, nil
	})

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
			encryptedKey, err := encrypter.Encrypt(context.Background(), privKeyBytes, nil)
			assert.NoError(t, err)
			assert.NotEmpty(t, encryptedKey)

			// decrypt the serviceKey using our service serviceKey
			decryptedKey, err := encrypter.Decrypt(context.Background(), encryptedKey, nil)
			assert.NoError(t, err)
			assert.NotEmpty(t, decryptedKey)

			// reconstruct the key from its serialized form
			privKeyReconstructed, err := crypto.BytesToPrivKey(decryptedKey, test.kt)
			assert.NoError(t, err)
			assert.EqualValues(t, privKey, privKeyReconstructed)
		})
	}
}
