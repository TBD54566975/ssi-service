package storage

import (
	"github.com/TBD54566975/ssi-sdk/crypto"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

// StoredKey represents a common data model to store data on all key types
type StoredKey struct {
	ID         string         `json:"id"`
	Controller string         `json:"controller"`
	KeyType    crypto.KeyType `json:"keyType"`
	Base58Key  string         `json:"key"`
	CreatedAt  string         `json:"createdAt"`
}

// KeyDetails represents a common data model to get information about a key, without revealing the key itself
type KeyDetails struct {
	ID         string         `json:"id"`
	Controller string         `json:"controller"`
	KeyType    crypto.KeyType `json:"keyType"`
	CreatedAt  string         `json:"createdAt"`
}

type ServiceKey struct {
	Base58Key  string
	Base58Salt string
}

type Storage interface {
	StoreKey(key StoredKey) error
	GetKey(id string) (*StoredKey, error)
	GetKeyDetails(id string) (*KeyDetails, error)
}

func NewKeyStoreStorage(s storage.ServiceStorage, serviceKey, serviceKeySalt string) (Storage, error) {
	switch s.Type() {
	case storage.Bolt:
		gotBolt, ok := s.(*storage.BoltDB)
		if !ok {
			return nil, util.LoggingNewErrorf("trouble instantiating : %s", s.Type())
		}
		boltStorage, err := NewBoltKeyStoreStorage(gotBolt, ServiceKey{
			Base58Key:  serviceKey,
			Base58Salt: serviceKeySalt,
		})
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not instantiate key store bolt storage")
		}
		return boltStorage, err
	default:
		return nil, util.LoggingNewErrorf("unsupported storage type: %s", s.Type())
	}
}
