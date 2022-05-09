package storage

import (
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type BoltCredentialStorage struct {
	db *storage.BoltDB
}

func NewBoltCredentialStorage(db *storage.BoltDB) (*BoltCredentialStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltCredentialStorage{db: db}, nil
}

func (b BoltCredentialStorage) StoreCredential(credential StoredCredential) error {
	//TODO implement me
	panic("implement me")
}

func (b BoltCredentialStorage) GetCredential(id string) (*StoredCredential, error) {
	//TODO implement me
	panic("implement me")
}

func (b BoltCredentialStorage) GetCredentialsByIssuer(issuer string) ([]StoredCredential, error) {
	//TODO implement me
	panic("implement me")
}

func (b BoltCredentialStorage) GetCredentialsBySubject(subject string) ([]StoredCredential, error) {
	//TODO implement me
	panic("implement me")
}

func (b BoltCredentialStorage) GetCredentialsBySchema(schema string) ([]StoredCredential, error) {
	//TODO implement me
	panic("implement me")
}

func (b BoltCredentialStorage) DeleteCredential(id string) error {
	//TODO implement me
	panic("implement me")
}
