package storage

import (
	"fmt"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace         = "keystore"
	skKey             = "ssi-service-key"
	keyNotFoundErrMsg = "key not found"
)

type BoltKeyStoreStorage struct {
	db *storage.BoltDB
}

func NewBoltKeyStoreStorage(db *storage.BoltDB, key ServiceKey) (*BoltKeyStoreStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}

	bolt := &BoltKeyStoreStorage{db: db}

	// first, store the service key
	if err := bolt.storeServiceKey(key); err != nil {
		return nil, errors.Wrap(err, "could not store service key")
	}
	return bolt, nil
}

// TODO(gabe): support more robust service key operations, including rotation, and caching
func (b BoltKeyStoreStorage) storeServiceKey(key ServiceKey) error {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not marshal service key")
	}
	if err := b.db.Write(namespace, skKey, keyBytes); err != nil {
		return util.LoggingErrorMsg(err, "could store marshal service key")
	}
	return nil
}

func (b BoltKeyStoreStorage) getServiceKey() (*ServiceKey, error) {
	skBytes, err := b.db.Read(namespace, skKey)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not retrieve service key")
	}
	var serviceKey ServiceKey
	if err := json.Unmarshal(skBytes, &serviceKey); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not unmarshal service key")
	}
	return &serviceKey, nil
}

func (b BoltKeyStoreStorage) StoreKey(key StoredKey) error {
	id := key.ID
	if id == "" {
		return util.LoggingNewError("could not store key without an ID")
	}

	keyBytes, err := json.Marshal(key)
	if err != nil {
		errMsg := fmt.Sprintf("could not store key: %s", id)
		return util.LoggingErrorMsg(err, errMsg)
	}
	return b.db.Write(namespace, id, keyBytes)
}

func (b BoltKeyStoreStorage) GetKeyDetails(id string) (*KeyDetails, error) {
	storedKeyBytes, err := b.db.Read(namespace, id)
	if err != nil {
		errMsg := fmt.Sprintf("could not get key details for key: %s", id)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	if len(storedKeyBytes) == 0 {
		err := fmt.Errorf("could not find key details for key: %s", id)
		return nil, util.LoggingError(err)
	}
	var stored StoredKey
	if err := json.Unmarshal(storedKeyBytes, &stored); err != nil {
		errMsg := fmt.Sprintf("could not unmarshal stored key: %s", id)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return &KeyDetails{
		ID:         stored.ID,
		Controller: stored.Controller,
		KeyType:    stored.KeyType,
		CreatedAt:  stored.CreatedAt,
	}, nil
}
