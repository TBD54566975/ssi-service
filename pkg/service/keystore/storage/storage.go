package storage

import (
	"fmt"

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

type Storage interface {
	StoreKey(key StoredKey) error
	GetKeyDetails(id string) (*KeyDetails, error)
}

func NewKeyStoreStorage(s storage.ServiceStorage, kekPassword string) (Storage, error) {
	switch s.Type() {
	case storage.Bolt:
		gotBolt, ok := s.(*storage.BoltDB)
		if !ok {
			errMsg := fmt.Sprintf("trouble instantiating : %s", s.Type())
			return nil, util.LoggingNewError(errMsg)
		}
		boltStorage, err := NewBoltKeyStoreStorage(gotBolt, kekPassword)
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not instantiate key store bolt storage")
		}
		return boltStorage, err
	default:
		errMsg := fmt.Errorf("unsupported storage type: %s", s.Type())
		return nil, util.LoggingError(errMsg)
	}
}
