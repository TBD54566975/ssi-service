package storage

import (
	"encoding/base64"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

// StoredKey represents a common data model to store data on all key types
type StoredKey struct {
	ID         string      `json:"id"`
	Controller string      `json:"controller"`
	KeyType    string      `json:"keyType"`
	Key        interface{} `json:"key"`
	CreatedAt  string      `json:"createdAt"`
}

// KeyDetails represents a common data model to get information about a key, without revealing the key itself
type KeyDetails struct {
	ID         string `json:"id"`
	Controller string `json:"controller"`
	KeyType    string `json:"keyType"`
	CreatedAt  string `json:"createdAt"`
}

type ServiceKey struct {
	Key  string
	Salt string
}

type Storage interface {
	StoreKey(key StoredKey) error
	GetKeyDetails(id string) (*KeyDetails, error)
}

func NewKeyStoreStorage(s storage.ServiceStorage, skPassword string) (Storage, error) {
	serviceKey, err := generateServiceKey(skPassword)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not generate service key")
	}

	switch s.Type() {
	case storage.Bolt:
		gotBolt, ok := s.(*storage.BoltDB)
		if !ok {
			errMsg := fmt.Sprintf("trouble instantiating : %s", s.Type())
			return nil, util.LoggingNewError(errMsg)
		}
		boltStorage, err := NewBoltKeyStoreStorage(gotBolt, *serviceKey)
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not instantiate key store bolt storage")
		}
		return boltStorage, err
	default:
		errMsg := fmt.Errorf("unsupported storage type: %s", s.Type())
		return nil, util.LoggingError(errMsg)
	}
}

// generateServiceKey using argon2 for key derivation generate a service key and corresponding salt,
// base66 encoding both values
func generateServiceKey(skPassword string) (*ServiceKey, error) {
	salt, err := util.GenerateSalt(util.Argon2SaltSize)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate salt for service key")
	}
	key, err := util.Argon2KeyGen(skPassword, salt, chacha20poly1305.KeySize)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate key for service key")
	}

	encoding := base64.StdEncoding
	return &ServiceKey{
		Key:  encoding.EncodeToString(key),
		Salt: encoding.EncodeToString(salt),
	}, nil
}
