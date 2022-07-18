package storage

import (
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace         = "keystore"
	keyNotFoundErrMsg = "key not found"
)

type BoltKeyStoreStorage struct {
	db *storage.BoltDB
}

func NewBoltKeyStoreStorage(db *storage.BoltDB) (*BoltKeyStoreStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltKeyStoreStorage{db: db}, nil
}

func (b BoltKeyStoreStorage) StoreKey(key StoredKey) error {
	// TODO implement me
	panic("implement me")
}

func (b BoltKeyStoreStorage) GetKeyDetails(id string) (*KeyDetails, error) {
	// TODO implement me
	panic("implement me")
}
