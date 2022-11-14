package storage

import (
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type BoltOperationStorage struct {
	db *storage.BoltDB
}

func (b BoltOperationStorage) StoreOperation(op StoredOperation) error {
	// TODO(andres) implement me
	panic("implement me")
}

func (b BoltOperationStorage) GetOperation(id string) (*StoredOperation, error) {
	// TODO(andres) implement me
	panic("implement me")
}

func (b BoltOperationStorage) GetOperations() ([]StoredOperation, error) {
	// TODO(andres) implement me
	panic("implement me")
}

func (b BoltOperationStorage) DeleteOperation(id string) error {
	// TODO(andres) implement me
	panic("implement me")
}

func NewBoltOperationStorage(db *storage.BoltDB) (*BoltOperationStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltOperationStorage{db: db}, nil

}
